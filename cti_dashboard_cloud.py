import os
import json
import feedparser
import newspaper
from newspaper import Article
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import streamlit as st
from groq import Groq
import time

# =====================================================================
# SETUP & UI CONFIGURATION
# =====================================================================
st.set_page_config(page_title="n8sec CTI Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ n8sec Automated CTI Triage Engine")
st.markdown("Monitoring priority intelligence requirements (PIRs) using the blazing-fast Groq API.")

# =====================================================================
# HYBRID AUTHENTICATION LOGIC
# =====================================================================
st.sidebar.header("Configuration")

# Check if the local secrets file exists
if "GROQ_API_KEY" in st.secrets:
    # 1. LOCAL MODE: Silently use your hidden key
    groq_api_key = st.secrets["GROQ_API_KEY"]
    st.sidebar.success("🔒 Local API Key Loaded")
else:
    # 2. CLOUD/PUBLIC MODE: Require the user to input their own key
    groq_api_key = st.sidebar.text_input("Enter your Groq API Key", type="password")
    if not groq_api_key:
        st.sidebar.warning("⚠️ Please provide a Groq API Key to run the pipeline.")
        st.sidebar.markdown("[Get a free key here](https://console.groq.com/keys)")

st.sidebar.header("Configuration")
cloud_model = st.sidebar.selectbox(
    "Select Groq Model",
    (
        "llama-3.3-70b-versatile", 
        "llama-3.1-8b-instant", 
        "mixtral-8x7b-32768"
    ) 
)

HISTORY_FILE = "processed_urls.txt"

MY_PIRS = """
1. Ransomware malware: Identify new and emerging ransomware variants, capabilities, infection chains and decryption methods.
2. Information or data breach: Determine capability and intent of adversaries compromising or disclosing information belonging to or impacting U.S.
3. RAT malware: Identify the impacted or targeted operating system or network device by Remote Access Trojans.
4. Business email compromise (BEC): Identify and characterize adversary TTPs and tools used in BEC schemes.
5. Information-stealer malware: Identify new and emerging information-stealer malware including capabilities, functionality and threat levels.
6. Fraud: Identify fraud activity that includes State, Local, Tribal Territorial (SLTT) governments, municipalities, K-12, and financial institutions.
7. Vulnerabilities: Identify vulnerabilities in software and hardware that are being actively exploited by adversaries.
8. Dark web cybercrime activity: Identify cybercrime activity on the dark web that poses a threat to U.S. interests, including the sale of stolen data, hacking tools, and illicit services. 
"""
# =====================================================================
# SIDEBAR TOOLS
# =====================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("🛠️ Engine Tools")

# Button to delete the local history file so the script re-reads old feeds
if st.sidebar.button("🗑️ Clear URL Cache"):
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
        st.sidebar.success("Cache cleared! The engine will re-scan all feeds on the next run.")
    else:
        st.sidebar.info("Cache is already empty.")

# =====================================================================
# CTI RSS FEED LIST (50+ Sources)
# =====================================================================
CTI_RSS_FEEDS = [
    # --- TIER 1: GOVERNMENT & CERT ALERTS (High Fidelity, Low Noise) ---
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://us-cert.cisa.gov/ncas/alerts.xml",
    "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    "https://cert.europa.eu/publications/rss",
    "https://jvn.jp/en/rss/jvn.rdf", # Japan CERT (Great for AP-focused threats)

    # --- TIER 2: VENDOR THREAT RESEARCH (The IOC Goldmines) ---
    "https://www.mandiant.com/resources/blog/rss.xml",
    "https://blog.talosintelligence.com/feeds/posts/default",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.crowdstrike.com/blog/feed/",
    "https://redcanary.com/blog/feed/",
    "https://www.sentinelone.com/blog/feed/",
    "https://securelist.com/feed/", # Kaspersky (Excellent for ransomware/stealers)
    "https://research.checkpoint.com/feed/",
    "https://news.sophos.com/en-us/category/threat-research/feed/",
    "https://www.welivesecurity.com/en/rss/feed", # ESET
    "https://www.proofpoint.com/us/rss.xml", # Top tier for BEC and Email threats
    "https://www.cybereason.com/blog/rss.xml",
    "https://www.malwarebytes.com/blog/feed",
    "https://www.trendmicro.com/en_us/research.rss",
    "https://symantec-enterprise-blogs.security.com/feed",
    "https://www.dragos.com/blog/feed/", # ICS/OT specific threats
    "https://www.fortinet.com/blog/threat-research/rss",
    "https://blogs.blackberry.com/en/feed",

    # --- TIER 3: VULNERABILITY & EXPLOIT TRACKING ---
    "https://isc.sans.edu/rssfeed_full.xml",
    "https://www.zerodayinitiative.com/rss/",
    "https://msrc.microsoft.com/blog/feed/", # Microsoft Security Response
    "https://blog.projectzero.com/feeds/posts/default", # Google Project Zero
    "https://vulners.com/rss.xml",
    "https://attackerkb.com/rss",

    # --- TIER 4: RAPID BREACH NEWS & STRATEGIC INTEL ---
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://therecord.media/feed/", # Recorded Future's news wing
    "https://www.darkreading.com/rss.xml",
    "https://krebsonsecurity.com/feed/",
    "https://www.cyberscoop.com/feed/",
    "https://www.csoonline.com/feed",
    "https://www.securityweek.com/feed/",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://thecyberexpress.com/feed/",
    "https://securityaffairs.co/wordpress/feed",
    "https://www.scmagazine.com/rss",
    "https://cybernews.com/feed/",

    # --- TIER 5: OSINT, DARK WEB, & HACKTIVISM ---
    "https://medium.com/feed/week-in-osint",
    "https://www.hackread.com/feed/",
    "https://grahamcluley.com/feed/",
    "https://www.schneier.com/feed/atom/",
    "https://www.tracelabs.org/blog/rss.xml",
    "https://intel471.com/blog/rss", # Great dark web cybercrime coverage
    "https://kela.com/feed/" # Dark web threat intel
]

# =====================================================================
# AUTOMATED INGESTION ENGINE
# =====================================================================
def load_processed_urls():
    if not os.path.exists(HISTORY_FILE):
        return set()
    with open(HISTORY_FILE, "r") as f:
        return set(line.strip() for line in f)

def save_processed_url(url):
    with open(HISTORY_FILE, "a") as f:
        f.write(f"{url}\n")

def get_new_articles(limit_per_feed=2):
    processed_urls = load_processed_urls()
    new_urls = []
    for feed_url in CTI_RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:limit_per_feed]:
                if entry.link not in processed_urls:
                    new_urls.append(entry.link)
                    save_processed_url(entry.link)
        except Exception:
            pass 
    return new_urls

def scrape_article(url):
    try:
        article = Article(url)
        article.download()
        article.parse()
        return article.title, article.text
    except Exception:
        return None, None

# =====================================================================
# GROQ API NLP FEATURE EXTRACTION
# =====================================================================
def get_groq_intel_features(article_text, selected_model, api_key):
    client = Groq(api_key=api_key)
    
    sliced_text = article_text[:5000] + "\n\n...[TEXT TRUNCATED]...\n\n" + article_text[-5000:] if len(article_text) > 10000 else article_text
    
    prompt = f"""
    You are an expert Cyber Threat Intelligence Analyst. 
    Map the following article against our Priority Intelligence Requirements (PIRs).
    
    Our PIRs:
    {MY_PIRS}
    
    Article Text:
    {sliced_text} 
    
    CRITICAL INSTRUCTIONS:
    - You MUST extract actual Indicators of Compromise (IOCs) such as IP addresses, domains, URLs, and file hashes found ONLY in the Article Text.
    - If no IOCs are found in the text, you MUST return an empty list [].
    - DO NOT make up data or use example placeholders.
    
    Return a strictly formatted JSON object matching this exact schema:
    {{
        "matched_pir": "String: The name of the PIR that best matches",
        "pir_relevance_score": 0.9, 
        "ioc_count": 5, 
        "extracted_iocs": ["string_1", "string_2"],
        "threat_actor_named": 1, 
        "summary": "String: A 2 sentence summary of the threat"
    }}
    """
    
    # The Backoff Loop: Try up to 3 times before giving up
    for attempt in range(3): 
        try:
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a strict CTI data extraction tool. You must ONLY output valid JSON. Do not include introductory or concluding text."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=selected_model,
                temperature=0,
                response_format={"type": "json_object"} 
            )
            
            raw_json = chat_completion.choices[0].message.content.strip()
            return json.loads(raw_json)
            
        except Exception as e:
            error_message = str(e).lower()
            if "429" in error_message or "rate_limit" in error_message:
                # If we hit the speed limit, tell Streamlit we are pausing
                st.toast(f"⏳ API speed limit reached. Pausing for 60 seconds to let the token bucket refill...")
                time.sleep(60) 
                continue 
            else:
                st.error(f"Groq API Error: {e}")
                return None
                
    return None # Returns None if all 3 attempts fail

# =====================================================================
# MACHINE LEARNING: DECISION TREE
# =====================================================================
@st.cache_resource 
def train_decision_tree():
    X_train = [
        [0.95, 8, 1, 9], [0.85, 2, 1, 7], [0.50, 0, 0, 5], 
        [0.20, 0, 0, 3], [0.80, 15, 0, 8], [0.40, 1, 0, 6]
    ]
    y_train = [2, 2, 1, 0, 2, 0] 
    clf = DecisionTreeClassifier(max_depth=4, random_state=42)
    clf.fit(X_train, y_train)
    return clf

# =====================================================================
# MAIN EXECUTION PIPELINE
# =====================================================================
if st.button("🚀 Run Cloud Threat Intel Pipeline"):

    clf_model = train_decision_tree()
    
    with st.spinner(f"Scanning feeds and analyzing with Groq {cloud_model}..."):
        incoming_urls = get_new_articles()
        
        if not incoming_urls:
            st.info("Pipeline finished: No new articles right now.")
        else:
            st.success(f"Found {len(incoming_urls)} new articles. Extracting intelligence...")
            master_ioc_list = []
            
            # --- PROGRESS BAR UI ---
            total_articles = len(incoming_urls)
            progress_bar = st.progress(0.0, text="Initializing Groq processing pipeline...")
            status_text = st.empty() # Creates a dynamic text box that updates in place
            
            for index, url in enumerate(incoming_urls):
                # Update the UI for the current article
                current_step = index + 1
                progress_percentage = float(current_step) / total_articles
                
                progress_bar.progress(progress_percentage, text=f"Analyzing article {current_step} of {total_articles}")
                status_text.caption(f"**Target:** {url}")
                
                # 1. Scrape
                title, text = scrape_article(url)
                if not text: continue
                    
                # 2. Extract AI Features
                nlp_features = get_groq_intel_features(text, cloud_model, groq_api_key)
                if not nlp_features: continue
                    
                # 3. ML Triage
                live_data = [[
                    nlp_features.get('pir_relevance_score', 0),
                    nlp_features.get('ioc_count', 0),
                    nlp_features.get('threat_actor_named', 0),
                    8 
                ]]
                
                rating = clf_model.predict(live_data)[0]
                
                # 4. Display Results
                if rating == 2:
                    st.error(f"🔴 **CRITICAL:** {title}")
                elif rating == 1:
                    st.warning(f"🟡 **MEDIUM:** {title}")
                else:
                    st.info(f"⚪ **DISCARD:** {title}")
                    
                extracted_iocs = nlp_features.get('extracted_iocs', [])
                for ioc in extracted_iocs:
                    master_ioc_list.append({
                        "IOC": ioc,
                        "Source Article": title,
                        "Matched PIR": nlp_features.get('matched_pir', 'Unknown'),
                        "URL": url
                    })
                    
                with st.expander("View Triage Details"):
                    st.write(f"**URL:** {url}")
                    st.write(f"**🎯 PIR Match:** {nlp_features.get('matched_pir')}")
                    st.write(f"**📝 Summary:** {nlp_features.get('summary')}")
                    
                    if extracted_iocs:
                        st.write("**🪲 Indicators of Compromise (IOCs):**")
                        st.code("\n".join(extracted_iocs), language="text") 
                    else:
                        st.write("**🪲 Indicators of Compromise (IOCs):** None detected.")
            
            # Clear the status text when the loop is totally finished
            status_text.empty()
            progress_bar.progress(1.0, text="✅ Pipeline execution complete!")

            if master_ioc_list:
                st.markdown("---")
                st.subheader("📥 Export Intelligence")
                df_iocs = pd.DataFrame(master_ioc_list)
                csv_data = df_iocs.to_csv(index=False).encode('utf-8')
                
                st.download_button(
                    label="Download All IOCs as CSV",
                    data=csv_data,
                    file_name="n8sec_extracted_iocs.csv",
                    mime="text/csv"
                )
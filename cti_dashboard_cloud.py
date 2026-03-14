import os
import json
import feedparser
import newspaper
from newspaper import Article
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import streamlit as st
from groq import Groq

# =====================================================================
# 1. SETUP & UI CONFIGURATION
# =====================================================================
st.set_page_config(page_title="n8sec CTI Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ n8sec Automated CTI Triage Engine")
st.markdown("Monitoring priority intelligence requirements (PIRs) using the blazing-fast Groq API.")

# Securely load the API key from .streamlit/secrets.toml
try:
    groq_api_key = st.secrets["GROQ_API_KEY"]
except KeyError:
    st.error("⚠️ GROQ_API_KEY not found. Please ensure `.streamlit/secrets.toml` is configured properly.")
    st.stop()

st.sidebar.header("Configuration")
cloud_model = st.sidebar.selectbox(
    "Select Groq Model",
    ("llama3-8b-8192", "llama3-70b-8192", "mixtral-8x7b-32768") 
)

HISTORY_FILE = "processed_urls.txt"

MY_PIRS = """
1. Ransomware malware: Identify new and emerging ransomware variants, capabilities, infection chains and decryption methods.
2. Information or data breach: Determine capability and intent of adversaries compromising or disclosing information belonging to or impacting us.
3. RAT malware: Identify the impacted or targeted operating system or network device by Remote Access Trojans.
4. Business email compromise (BEC): Identify and characterize adversary TTPs and tools used in BEC schemes.
5. Information-stealer malware: Identify new and emerging information-stealer malware including capabilities, functionality and threat levels.
6. Fraud: Identify fraud activity that includes State, Local, Tribal Territorial (SLTT) governments, municipalities and K-12 
"""

# =====================================================================
# 2. THE CTI RSS FEED LIST 
# =====================================================================
CTI_RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://krebsonsecurity.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.mandiant.com/resources/blog/rss.xml",
    "https://blog.talosintelligence.com/feeds/posts/default",
    # Add the rest of your 30+ feeds back in here!
]

# =====================================================================
# 3. AUTOMATED INGESTION ENGINE
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
# 4. GROQ API NLP FEATURE EXTRACTION
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
        st.error(f"Groq API Error: {e}")
        return None

# =====================================================================
# 5. MACHINE LEARNING: DECISION TREE
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
# 6. MAIN EXECUTION PIPELINE
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
            
            for url in incoming_urls:
                title, text = scrape_article(url)
                if not text: continue
                    
                nlp_features = get_groq_intel_features(text, cloud_model, groq_api_key)
                if not nlp_features: continue
                    
                live_data = [[
                    nlp_features.get('pir_relevance_score', 0),
                    nlp_features.get('ioc_count', 0),
                    nlp_features.get('threat_actor_named', 0),
                    8 
                ]]
                
                rating = clf_model.predict(live_data)[0]
                
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
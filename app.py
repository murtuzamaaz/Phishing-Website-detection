import streamlit as st
import pickle
import sys
import pandas as pd  # Add current directory to path
from feature_extraction import extract_phishing_features  # Import the function from your existing script
import sys




def load_model():
    try:
        # Replace 'model.pkl' with the actual path to your pickle file
        with open(r'C:\Users\Maaz\Desktop\New folder\phising website detector\model.pkl', 'rb') as file:
            model = pickle.load(file)
        return model
    except FileNotFoundError:
        st.error("Model file not found. Please upload the pickle file.")
        return None

def predict_phishing(url):
    # Extract features
    features = extract_phishing_features(url)
    
    # Load the model
    model = load_model()
    
    if model is None:
        return None
    
    # Ensure features are in a DataFrame with proper column names
    feature_columns = [
        "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection", 
        "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record", 
        "Web_Traffic", "Domain_Age", "Domain_End", "iFrame", 
        "Mouse_Over", "Right_Click", "Web_Forwards"
    ]
    
    # Convert features to a DataFrame
    features_df = pd.DataFrame([features], columns=feature_columns)
    
    # Make prediction
    prediction = model.predict(features_df)
    return prediction[0]


def main():
    # Set page configuration
   
    st.set_page_config(
        page_title="Phishing Website Detector", 
        page_icon="🕵️",
        layout="wide"
    )
   
    # Custom CSS for styling
    st.markdown("""
    <style>
    .main-container {
        background-color: #f0f2f6;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .stTextInput > div > div > input {
        border: 2px solid #3498db;
        border-radius: 5px;
        padding: 10px;
    }
    .stButton > button {
        background-color: #2ecc71;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        font-weight: bold;
    }
    .stButton > button:hover {
        background-color: #27ae60;
    }
    .result-container {
        background-color: white;
        border-radius: 10px;
        padding: 1rem;
        margin-top: 1rem;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    </style>
    """, unsafe_allow_html=True)

    # Title and description
    st.title("🕵️ Phishing Website Detection")
    st.markdown("Enter a URL to check if it's a potential phishing website.")

    # URL input
    url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    
    # Prediction button
    if st.button("Detect Phishing"):
        if url:
            with st.spinner('Analyzing URL...'):
            
                try:
                    # Make prediction
                    prediction = predict_phishing(url)
                    
                    # Display results
                    if prediction is not None:
                        if prediction == 1:
                            st.error("⚠️ WARNING: This URL appears to be a PHISHING website!")
                            st.warning("Exercise caution and do not share personal information.")
                        else:
                            st.success("✅ This URL seems to be SAFE.")
                    
                    # Feature explanation section
                    st.markdown("### Feature Analysis")
                    
                    # Extract features for display
                    features = extract_phishing_features(url)
                    feature_names = [
                        "IP Address", "@ Symbol", "Long URL", "Deep URL Path", 
                        "Multiple Redirects", "HTTPS", "URL Shortener", 
                        "Domain with Hyphens", "No DNS Record", "Poor Web Traffic", 
                        "New Domain", "Short Domain Expiration", "iFrame", 
                        "Mouse Over Script", "Disabled Right Click", "Multiple Forwards"
                    ]
                    
                    # Create a features dataframe
                    feature_df = pd.DataFrame({
                        'Feature': feature_names,
                        'Suspicious': features
                    })
                    
                    # Highlight suspicious features
                    st.dataframe(
                        feature_df.style.apply(lambda x: ['background-color: red' if val == 1 else '' for val in x], subset=['Suspicious']),
                        hide_index=True
                    )
                
                except Exception as e:
                    st.error(f"Error analyzing URL: {str(e)}")
        else:
            st.warning("Please enter a valid URL")

    # Additional information
    st.markdown("\n### About Phishing Detection")
    st.markdown("""
    This tool uses machine learning to analyze various characteristics of a URL 
    to determine if it might be a phishing website. Key indicators include:
    - Unusual domain characteristics
    - Suspicious URL structures
    - Potential security risks
    """)

if __name__ == "__main__":
    main()
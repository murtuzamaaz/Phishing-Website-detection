
# 🔐 Phishing Website Detection  

## 📌 Overview  
This project is a **Phishing Website Detection** system using the **Random Forest Classifier**. It predicts whether a given website is legitimate or phishing based on various extracted features.  

## 📊 Dataset Features  
The dataset includes several features that help distinguish phishing websites from legitimate ones:  

- 🌐 **Have_IP**  
- 📧 **Have_At**  
- 🔗 **URL_Length**  
- 📏 **URL_Depth**  
- 🔄 **Redirection**  
- 🔒 **https_Domain**  
- 🔽 **TinyURL**  
- ➕ **Prefix/Suffix**  
- 📡 **DNS_Record**  
- 📈 **Web_Traffic**  
- ⏳ **Domain_Age**  
- 📆 **Domain_End**  
- 🖼 **iFrame**  
- 🖱 **Mouse_Over**  
- 🛑 **Right_Click**  
- 🚀 **Web_Forwards**  

## 🛠 Requirements  
Install the required dependencies:  
```bash
pip install -r req.txt
```

## 🚀 Usage  

1️⃣ **Clone the Repository**  
```bash
git clone <repo_link>
cd phishing-website-detection
```

2️⃣ **Install Dependencies**  
```bash
pip install -r req.txt
```

3️⃣ **Run the Model**  
```python
python predict.py
```

4️⃣ **Deploy the App (if applicable)**  
If you have a Streamlit app:  
```bash
streamlit run app.py
```

## 🏆 Model Details  
- 🤖 **Algorithm Used**: Random Forest Classifier  
- 🎯 **Training Process**: The model was trained on a dataset with an 80-20 train-test split.  
- 📊 **Performance Metrics**: Evaluated using accuracy, precision, and recall.  

## 🖼 App UI Screenshots  
Here are some images showcasing the final application interface:  
![Picture1](https://github.com/user-attachments/assets/d8b3bd91-bdfa-4861-8dae-c1228bae9b30)
![Picture2](https://github.com/user-attachments/assets/9031db85-58b2-4ae3-8a69-e9ac702b9918)
![Picture3](https://github.com/user-attachments/assets/84cf7830-93da-4c83-a351-ec5fe3a924bf)
![Picture4](https://github.com/user-attachments/assets/5aaaa3e4-ba54-4da7-ae91-eaa04e9d8133)

## 🤝 Contributing  
Feel free to fork this repository and contribute! If you find any issues, open a pull request or create an issue.  

## 📜 License  
This project is licensed under the **MIT License**.  

---

Let me know if you'd like any additional tweaks! 🚀🔍

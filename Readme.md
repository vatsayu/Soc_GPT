# SOC-GPT – AI SOC Analyst Assistant

Junior SOC analyst agent built with Streamlit + Groq (Llama 3.3 70B) + LangChain.

### Features
- Upload logs/files/emails → magic file type detection (from my P1 project)
- Content preview + IOC extraction
- AI analysis: threats, suspicion level, Sigma/YARA suggestions, MITRE mapping
- Conversation memory

### Tech Stack
- Python / Streamlit
- Groq API (free tier)
- LangChain (chains + memory)
- Custom tools: file_type_analyzer (P1 reuse), ioc_extractor

### Screenshots
![demo](images/demo.png)  <!-- upload 3-4 screenshots here -->

### Run Locally
```bash
cd SOC_GPT
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
streamlit run app.py
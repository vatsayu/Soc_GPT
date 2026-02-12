import streamlit as st
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_classic.memory import ConversationBufferMemory
from langchain_classic.chains import LLMChain
from dotenv import load_dotenv
from tools.file_type_analyzer import detect_file_type
from tools.ioc_extractor import extract_iocs   # fixed typo + correct path
import os

load_dotenv()

# ── LLM Setup ────────────────────────────────────────────
llm = ChatGroq(
    model="llama-3.3-70b-versatile",   # confirmed active/supported in Feb 2026
    temperature=0.6,
    api_key=os.getenv("GROQ_API_KEY")  # ← MUST come from .env – REMOVE hardcoded value!
)

system_prompt = """You are SOC-GPT – a junior SOC analyst assistant.
Analyze logs, files, emails, IOCs for threats.
Be concise, factual, use security terminology.
Suggest detections (Sigma, YARA, etc.), MITRE mappings, and next steps.
If file info is provided, comment on type, suspicion and potential threats."""

prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("human", "{input}")
])

# ── Memory & Chain (created once, outside loops) ────────
if "memory" not in st.session_state:
    st.session_state.memory = ConversationBufferMemory(
        memory_key="chat_history",
        return_messages=True
    )

llm_chain = LLMChain(
    llm=llm,
    prompt=prompt,
    memory=st.session_state.memory,
    verbose=False
)

# ── Streamlit Config ─────────────────────────────────────
st.set_page_config(page_title="SOC-GPT 🛡️", layout="wide")

# Custom chat styling
st.markdown("""
<style>
    .stChatMessage.user { background-color: #1f2937; }
    .stChatMessage.assistant { background-color: #2d3748; }
</style>
""", unsafe_allow_html=True)

st.title("SOC-GPT – AI SOC Assistant")
st.caption("Upload suspicious files, logs, emails or ask security questions")

# ── Chat History ─────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# ── Sidebar: File Upload & Processing ────────────────────
with st.sidebar:
    st.header("Evidence Upload")
    uploaded_file = st.file_uploader(
        "Log / .eml / suspicious file",
        type=["log", "txt", "evtx", "eml", "pdf", "jpg", "png", "exe", "dll"],
        help="Files up to ~10 MB recommended"
    )

    file_context = ""

    if uploaded_file is not None:
        try:
            file_bytes = uploaded_file.getvalue()
            type_result = detect_file_type(file_bytes[:16384])

            file_context = (
                f"**Uploaded file:** {uploaded_file.name}\n"
                f"**Size:** {len(file_bytes) / 1024:.1f} KB\n"
                f"**Real file type (magic):** {type_result['type']}\n"
                f"**Description:** {type_result['description']}\n"
                f"**Suspicion level:** {type_result['suspicious']}\n"
            )

            # Text preview
            try:
                preview = file_bytes[:1200].decode("utf-8", errors="ignore").strip()
                if preview:
                    file_context += f"\n**Content preview (first lines):**\n```\n{preview}...\n```"

                    # Extract IOCs from preview (fixed scope)
                    iocs = extract_iocs(preview)
                    if iocs:
                        file_context += "\n**Extracted IOCs:**\n"
                        for typ, vals in iocs.items():
                            file_context += f"- **{typ.upper()}:** {', '.join(vals)}\n"
            except:
                file_context += "\n**(Binary file – no text preview)**"

            st.success("File processed!")
            st.markdown(file_context)

        except Exception as e:
            st.error(f"Error processing file: {str(e)}")
            file_context = f"**File processing failed:** {str(e)}"

# ── Chat Input & Response ────────────────────────────────
if user_input := st.chat_input("Ask about security, describe IOCs, paste log lines..."):
    full_prompt = user_input
    if file_context:
        full_prompt += f"\n\n--- Uploaded Evidence ---\n{file_context}"

    # Display user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)
        if file_context:
            st.caption(f"Attached: {uploaded_file.name if uploaded_file else '—'}")

    # Generate & display assistant response
    with st.chat_message("assistant"):
        with st.spinner("Analyzing..."):
            try:
                response = llm_chain({"input": full_prompt})
                assistant_reply = response["text"]
                st.markdown(assistant_reply)
            except Exception as e:
                error_msg = f"LLM error: {str(e)}"
                st.error(error_msg)
                assistant_reply = error_msg

    st.session_state.messages.append({"role": "assistant", "content": assistant_reply})

# ── Utility Buttons ──────────────────────────────────────
if st.button("Clear conversation", use_container_width=True):
    st.session_state.messages = []
    st.session_state.memory.clear()  # also reset memory
    st.rerun()
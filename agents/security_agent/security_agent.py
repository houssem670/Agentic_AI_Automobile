from langchain_ollama import ChatOllama


llm = ChatOllama(   
    model="llama3.2:3b",
    temperature=0
)


def security_agent(event): 

    prompt = f"""
You are an automotive cybersecurity analyst.

Analyze ONLY the CAN security event provided below.

IMPORTANT RULES:
- Do not invent measurements.
- Do not invent CAN specifications.
- Do not assume a CAN ID is legitimate or malicious without evidence.
- Do not confuse the observation window with CAN frame duration.
- Use the exact values provided in the event.
- If information is missing, explicitly say "Unknown".
- The threshold is the anomaly detection threshold in messages per second.

CAN SECURITY EVENT:

CAN ID: {event["can_id"]}                                                                     
Message count: {event["message_count"]}     
Observation window: {event["window_seconds"]} seconds
Observed rate: {event["observed_rate"]} messages/second
Detection threshold: {event["threshold"]} messages/second
Anomaly detected: {event["anomaly"]}
Attack type: {event["attack_type"]}

Provide the analysis using exactly these sections:

1. Event Analysis
2. Detected Threat
3. Risk Level
4. Evidence
5. Recommended Investigation
6. Recommended Mitigation

Base every conclusion on the provided evidence.
"""

    response = llm.invoke(prompt)

    return response.content     
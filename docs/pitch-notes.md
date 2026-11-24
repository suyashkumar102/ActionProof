# 90-second demo

1. **0-15s:** “An agent may be manipulated by untrusted content. A generic approval to use a tool is too broad.”
2. **15-35s:** Click **Safe internal email**. It is policy allowed and lands in the simulated mailbox.
3. **35-55s:** Click **Protected-file exfiltration**. The policy blocks `confidential_q4.pdf` before the mailbox is contacted.
4. **55-80s:** Click **Approval tampering**, approve `alice@partner.test`, then attempt the altered recipient. The evidence strip proves the approval and attempted action differ and that unauthorized mail count is zero.
5. **80-90s:** “Agents can propose; only the exact action the user approved can execute.”

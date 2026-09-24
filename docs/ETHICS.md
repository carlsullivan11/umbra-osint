# Ethics & lawful use

**Product stance (operator policy, 2026-08-15):**  
Umbra’s use policy is grounded in **lawfulness**. For product design and enforcement **at this stage**:

> **If an investigation or technique is lawful in the operator’s applicable jurisdiction(s), it is in-bounds for Umbra. If it is unlawful, it is out of bounds.**

Umbra does **not** add a separate moral code on top of the law for feature gating. Operators remain solely responsible for knowing and following the law that applies to them.

This is **not legal advice**. Laws differ by country, state, and facts. “Public data” is not automatically lawful to collect or use in every context.

---

## 1. Framework

| Question | Outcome |
|----------|---------|
| Is the activity **illegal** where you operate / where the target systems sit / under laws that apply to you? | **Do not use Umbra for it** |
| Is the activity **legal** under those laws? | **Allowed** under this product policy |
| Unsure? | Stop and obtain competent legal advice before proceeding |

### Always illegal → always prohibited in Umbra
Examples (non-exhaustive; still illegal in essentially all serious jurisdictions):

- Child sexual abuse material (CSAM) — access, possession, distribution  
- Computer intrusion / unauthorized access to systems, accounts, or data (e.g. hacking, credential stuffing, bypassing access controls you are not allowed to bypass)  
- Fraud, extortion, blackmail facilitation  
- Purchasing or trafficking stolen data or criminal market access as a participant  
- Harassment/stalking/doxxing **where those are criminal offenses** under applicable law  
- Sanctions evasion or other clearly prohibited transactions  

Umbra must not be used as infrastructure for those activities. Hard stops and refusal paths may exist in software for clear illegal categories (e.g. CSAM).

### Lawful open-source investigation
Using publicly available information, passive DNS, CT logs, published breach notification APIs you are entitled to query, etc., can be lawful when done in compliance with applicable law, contracts, and access rules. **You** must ensure that is true for your case.

---

## 2. Operator legal responsibility

By using Umbra you agree that:

1. **You** determine lawfulness for each case (purpose, target, method, jurisdiction).  
2. **You** supply and stand behind an **authorization basis** string on every case — a short record of *why this investigation is lawful* (e.g. asset you own, written client scope, employment duty, own research on public data under your laws). This is a **compliance aid and audit artifact**, not a moral judgment by Umbra.  
3. **You** comply with computer misuse, privacy, wiretap/intercept, CFAA-equivalent, export, employment, and contract law that applies to you.  
4. **You** comply with third-party **Terms of Service** and rate limits of sources you query — breach of contract can create legal risk even when “data is public.”  
5. **You** configure API keys and infrastructure lawfully.  
6. Umbra authors and hosts are **not** your counsel and **not** liable for your misuse.

---

## 3. Product controls (legal risk reduction — not extra morality)

These exist to reduce **illegal misuse** and preserve evidence of lawful purpose:

| Control | Legal rationale |
|---------|-----------------|
| Mandatory **authorization_basis** on cases | Documents asserted lawful purpose; audit trail. The **web UI no longer offers a chooser** — an anonymous visitor asserting a basis documents nothing, so web cases record `other` plus a note saying none was asserted. The CLI still takes an explicit `-b`. |
| **Audit logging** of runs | Forensic trail if misuse is alleged |
| Rate limits / fair use (hosted) | Reduces platform abuse and unlawful bulk harm |
| API keys & entitlements | Accountability for cloud actions |
| Passive-only dark-web exposure paths | Avoids participation in criminal markets (often illegal) |
| No buy-flow / no marketplace features | Avoids trafficking/stolen goods facilitation |
| Hosted AUP enforcement | Operator may suspend accounts used for illegal activity |
| MAC lookup never resolves a locally administered address | A randomized/private Wi-Fi address has no registrant; naming a "vendor" for one invents a fact, and treating it as a durable device ID is the first step toward device tracking of a person |
| Server stack fingerprint recorded only from a fetch the operator already authorized | Fingerprinting **a server you asked about** is not fingerprinting **the people who visit you**: `fp_*` props come from the one handshake and GET a lookup already makes, and Umbra never fingerprints its own visitors or connects back to an IP that scanned it |
| News feed polls public official/reputable sources only | No credentialed or paywalled scraping; feed items are labelled **signals, not findings** so a headline is never mistaken for a verified fact about someone |
| **Person-name search requires a declared basis** (N1, 2026-09-14) | A name asks about a person; a domain asks about infrastructure. `/people`, `/records` and their `/v1` siblings now require an authorization basis, shown **above** the FCRA and identity-match caveats rather than under the results, and write one `person_search.declared` audit row. Umbra does not verify the declaration — the value is the deliberate act, the record that the caveats were seen, and the ability to answer later how the tool was used. **Only the query's shape is stored** (tokens, length, whether a state filter was set), never the name: a log of who looked up whom would be a worse privacy object than the search it audits. It never sets `Case.authorization_basis`, which stays an authority claim the web cannot make |

Feature design priority: **do not ship capabilities whose primary purpose is the commission of crime.** Dual-use OSINT tools are normal; intentional crimeware is not.

### Module-specific boundaries

| Module | In scope | Explicitly out |
|--------|----------|----------------|
| MAC / OUI (`docs/COLLECTORS.md`, `umbra mac`) | Asset attribution: "what is this NIC on my network?" — offline registry lookup, layer-2 facts | Device stalking, presence tracking, or any claim to geolocate a MAC. Every result states that a MAC is not routable and not geolocatable from the address |
| Animal-abuse registry (`docs/ANIMAL-REGISTRY.md`, `umbra animal-registry`) | Official, cited findings — convictions, pleas, government registry listings, civil orders — with delisting, retention and a dispute path | Charges or accusations as entries; publishing an unlinked report; street addresses, DOBs or photos; republishing a registry whose access terms forbid it. An open dispute hides the entry until a reviewer resolves it |
| Cyber news feed (`docs/FEED.md`) | Defensive situational awareness from official advisories | Person-centric or social-stalking queries; scraping behind logins; copying article bodies (links only) |

---

## 4. Dark-web and breach data (law-focused)

**Often unlawful or high-risk:** buying dumps, logging into criminal forums with payment, dealing in stolen credentials as a commodity, distributing leak contents.

**May be lawful when carefully scoped:** querying **lawful** breach-notification APIs (e.g. HIBP with proper authorization), or **passively** learning that an asset you are legally allowed to monitor appeared in a **already-public** source — without purchasing access or redistributing stolen content. See `docs/BREACH-AND-MONITORING.md`.

Store **facts of exposure** (pointer, hash, date), not a pirated library of stolen records, unless you have a lawful basis to retain more.

---

## 5. Hosted service (when applicable)

- Free core and paid advanced features remain subject to **Terms**, **Privacy Policy**, and **Acceptable Use Policy**.  
- AUP tracks **illegality and abuse of the service**, not taste.  
- Violations of law or AUP → suspension, key revocation, referral to law enforcement when required.

---

## 6. Changes

If product policy later adds stricter-than-law standards, that will be an explicit versioned change. Until then, **lawfulness is the ethics framework.**

---

## 7. Quick checklist for operators

- [ ] I have a lawful purpose and jurisdiction analysis I’m willing to defend  
- [ ] Authorization basis on the case is accurate  
- [ ] Methods don’t require unauthorized access or illegal purchases  
- [ ] Source ToS and rate limits respected  
- [ ] No CSAM or other per-se illegal content  
- [ ] If unsure → legal counsel, not “ship it”  

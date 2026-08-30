# How Project Umbra Was Made

Project Umbra began as a product question: could a personal privacy agent carry the repetitive investigation work without taking consequential decisions away from the user?

The finished project grew through a deliberately mixed workflow. Specialized AI and cloud tools handled different parts of the process, while the creator directed the product, reviewed the evidence, and made the final decisions.

## From idea to prototype

Gemini helped explore several product directions and develop the selected idea into an end-to-end concept. The creator then used Google Antigravity's early subagent teamwork preview to coordinate a parallel prototype sprint across product strategy, architecture, interface design, implementation, testing, and documentation.

At its peak, the sprint involved approximately twelve agents. The creator estimates that it produced roughly 70% of the foundation that evolved into the finished product. Those figures describe the observed creation process; they are not automated code-contribution measurements.

## The production system

Project Umbra uses:

- **Gemini 3.7 Flash** through the **Google GenAI SDK** to turn supported source material into validated, structured evidence;
- **Cloud Run** to host the application and background mission runtime;
- **Firestore** to persist cloud mission state, telemetry, findings, and action records;
- **Cloud Build** and **Artifact Registry** to build and store deployable images;
- **Secret Manager**, **IAM**, the **API Keys API**, and **Cloud Logging** to protect and observe the hosted service.

The runtime keeps investigation separate from external action. Umbra prepares an evidence-backed plan, and the user decides whether to proceed through an official broker workflow.

## The Gemma experiment

Umbra also implements and tests an optional **Gemma 2 9B IT** path for neural PII classification. The production configuration uses deterministic classification because it provides a more predictable privacy boundary. If the optional neural path fails, the classifier falls back to deterministic rules.

The repository includes the Gemma path as an implemented and tested secondary design. It does not claim that Gemma inference ran in the demonstrated production mission.

## Voice and visual production

Google AI also supported the demonstration:

- **Google Flow** provided a workspace for generative imagery, motion exploration, scene development, and selected edits;
- **Gemini Omni Flash** supported conversational visual refinement inside Flow;
- **Veo** generated motion material used during the video-production process;
- **Google Cloud Text-to-Speech** synthesized the narration with `en-US-Journey-F`, a Journey voice now branded as Chirp HD.

The final product interface, exact typography, architecture labels, captions, and evidence surfaces were composed from native source material so critical text stayed readable and stable.

## What the process revealed

The most important result was not one model or feature. It was the strength of the Google AI ecosystem as a collection of specialized systems.

Antigravity coordinated agent work. Gemini structured application evidence. Gemma supported focused model experimentation. Flow, Omni, and Veo supported visual production. Cloud Text-to-Speech handled narration. Google Cloud hosted, secured, persisted, and observed the product.

That specialization produced strong results at each layer. It also exposed an integration opportunity: project context still moves between Antigravity, Flow, the Google Cloud Console, Firestore, and the surrounding production tools. A unified developer workspace could preserve these specialized capabilities while carrying shared context, assets, permissions, deployment state, and evidence across the full lifecycle.

Project Umbra demonstrates that this integrated Google workflow is already powerful when assembled deliberately.

## Additional tools and authorship

OpenAI Codex assisted with implementation, tests, critique, security review, documentation, and local video production. HyperFrames and FFmpeg supported deterministic composition, captioning, and media delivery. The creator selected the direction, evaluated the outputs, corrected the claims, and owns the resulting project.

For the product architecture and its trust boundaries, see [ARCHITECTURE.md](ARCHITECTURE.md). For setup and testing, see [README.md](README.md).

# Problem Definition

### 1. Specific Problem this addresses

When dealing with a lot of screenshots, either for creating documentation, sharing knowledge, or producing evidence as part of a GRC audit, it is easy to accidentally include secrets, passwords, IP’s, API keys, tokens, ect which leaks information. For technical users, this serves as a second check; for non-technical users who may not recognize sensitive information as readily, this serves as a learning tool and also a second check.



### 2. Why is this problem important

It is easy to overlook an object in the background or sidebar of an image and accidentally leak information when producing and using screenshots.



### 3. Existing tools or approaches

There are existing tools that can help do this; for example, Jira has the capability to do this. Any agents or LLM powered tools can easily do this as well. These tools are not free, and in cases of AI, there are data privacy issues if not using an enterprise version that keeps prompt data safe.



### 4. What Gap does this tool fill

This tool fills the gap that free OCR secret detection that runs locally and does not utilize AI in its decision making is very limited.



# System Design

### 1. High-Level Architecture

* core.py — preprocessing and OCR; it handles adaptive upscale, dark-mode invert, OCR-in-bands for tall/mixed pages, and does OCR via Tesseract, producing words with bounding boxes.
* detect.py — YAML-defined detectors, generate candidates; reject-only validators filter false positives; dedupe merges overlapping hits.
* app.py — Handles the front end web UI.



### 2. Technological choices and justification

* Tesseract OCR — this is free, local, with no API, and no network, keep data private and local. A cloud OCR would mean uploading screenshots full of secrets, which contradicts the tool's purpose.

* Rules  — deterministic, explainable, reproducible by classmates, and fixable in one line. No training data for "screenshots-with-secrets" exists anyway.

* Python + Pillow/NumPy — mature OCR/imaging 

* Streamlit — a functional web UI in minimal code

* Docker — one reproducible command; pins Tesseract version so results don't drift between machines.



# Evaluation

### 1. How I tested

  I added an OCR output to the web page and was able to run screenshots and detect what language was captured. This helped narrow down whether it was an OCR processing problem or a rule-matching problem. When possible, I took my own screenshots or found examples online. Later, I had Claude AI generate a sample set of images.

### 2. Results

  OCR is not perfect, and it often makes mistakes. In general, things work as expected, but certain combinations of color and text, or GUI markings, may cause the OCR to not recognize the text in certain cases. General issues had to be worked out and fixed, but not all possibilities have been accounted for.



### 3. Known Issues

While it supports multiple input types, JPEG functions the worst and PNG’s function the best. This is a general behavior with OCR since the former is compressed and the latter is lossless.

Sometimes the boxes to redact text do not fully cover the text; I think having them human resizable in the future would make sense, but this has to do with the detection rules and at times, the way OCR reads text.

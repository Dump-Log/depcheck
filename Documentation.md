Problem Definition

1. Specific Problem this addresses

* This tool attempts to first identify potential typos or likely typo-squatting attacks, allowing a user to audit their own and others' requirements.txt files.
* Secondly, it attempts to clearly show the CVEs for both direct dependencies and transitive dependencies.

2. Why is this problem important

* When cloning projects from GitHub in Python, they often include a requirements.txt file, which installs the required dependencies to run the project. These dependencies can be, at best, strong and secure, but at worst, full of known security risks or even vulnerable to an attack called Typosquatting. This is when a threat actor uploads a malicious library to PyPI that is similar to a known package, hoping someone will make a typo and use their malicious package instead. 

3. Existing tools or approaches

* There are many tools to securely audit dependencies, in fact, depcheck uses pip-audit, which is a well-supported and popular tool for auditing Python dependencies.
* For the typosquatting, I was able to find a few open source projects that attempted to do the same, but the signals used to determine where they differ.

4. What Gap does this tool fill

* This shows multiple signals indicating a suspicious package, most notably the use of the Levenshtein distance. This is the number of single-character edits between two words. So, in addition to providing CVE’s for dependencies, it also uses Levenshtein distance to flag suspicious packages, providing more traditional IOC information.

System Design

1. High-Level Architecture

* The Project is split into 2 files
  * analyze.py - all logic, no UI, when called, it runs 3 independent tasks
    * 1 Vulnerability scan - uses pip-audit to resolve the full transitive dependence tree and checks them against the OSV advisory database. If a package fails to resolve, it does a binary search to determine which package is not resolvable. These are marked as not found and highlighted in the UI.
    * 2 Typosquat Detection -  downloads the top 10,000 packages from PyPI for the ground truth list. For each dependency in the requirements.txt, it computes Levenshtein distance against the top 10,000 and flags suspicious findings. MetaData is fetched from the PyPI JSON API concurrently and assigned a score of 0.0-1.0.
    * 3 Results - Both 1 & 2 return a single AnalysisResult dataclass, which is passed to the UI
  * app.py - Steamlit frontend. It accepts a GitHub URL to a requirements.txt, or you can upload a local requirements.txt. It calls analyze(), and produces the results as an interactive web page.

2. Technological choices and justification

* Levenshtein distance to determine if two words are similar, this is used to detect possible typos, a well known algorithm, and is fast.
* pip-audit, a well known pyhton dependency security audit tool, provides the information needed and functions well.
* Docker -  To help make reproducibility easier, this is bundled as a Docker, and users can either build it themself, or use the image hosted on Docker Hub to run it.

Evaluation

1. How I tested

* I created an example requirements.txt file and specifically identified packages with similar names, such as panadas instead of pandas, so it could find similar names and generate results.

2. Results

* As expected, it found the proper similar package and provided the relevant information in the web UI

3. Known Issues

* If a typo resulted in multiple hits that are Levenshtein distance 1 away, it may not report on each one. It was hard to test this, and it is very unlikely that a requirements.txt would have multiple typosquatting attacks to the top 10,000 packages.
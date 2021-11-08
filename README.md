# Security99
Cloud Innovation Centre powered by AWS, 
RMIT University, Cohort July 2021
Team Security99



**Problem Statement:**
	“How might we increase the capability of ANZ SMBs to better respond to cyber-attacks by helping developers to track vulnerabilities & secure lengthy code before it gets deployed into production?”
 


**Solution:**
  CodeSecure - a solution that is built to analyse code and provide security insights at the early stages of product development to help reduce cyber risk.  CodeSecure does the work of mitigating vulnerabilities. It is an online code analyser feature integrated with AWS (Amazon Web Services) Code Pipeline that helps identify vulnerabilities. t identifies static code and provides suggestions to handle security fixes. The development team now has easy access to an overview of security misconfigurations in the solution. 




**Features:**

   - Uses data based on issues identified in more than 100 open-source security tools.
   - Both Reporting & Dashboarding of code vulnerabilities are made available.
   - Easy to use. 
   - Suggests security measures to be implemented to mitigate the security vulnerabilities.
   - Lower cost & secure.
   - Effective and rich with knowledge.



**Installation Steps:**


- Watch the demo video and ppt (Refer Case Study) & the CodeSecure documentation to understand the architecture & working of the application.
- Note: The contents of the "csTemplate.yaml" only covers the basic template for the resources used in developing CodeSecure in a individual manner and does not provide a one tap replication of CodeSecure. Please refer to the demo video to replicate CodeSecure exactly how it was made by team Security99. Replace '(region)-(AWS Account ID here)' in the document with your region and AWS Account ID
- Docker Image Creation:
	
  - Install Docker
  - In the root folder of the repository, run the "docker build" command. A docker image with name 'codesecure-app:latest' will be created.
  - Investigate the docker image folder for further information.

- Note: 'test-import-vulnerable-api-master' source code has vulnerabilities in it and can be used for testing purpose.


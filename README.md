POLICY-AS-CODE-RBAC
This repository implements Policy as Code using Open Policy Agent (OPA) and Gatekeeper to enforce Role-Based Access Control (RBAC) in Kubernetes environments.

Features:
1. Authored Policies in Rego
   - Wrote RBAC and access control policies in [Rego]
   - Committed them to GitHub for version control.  

2. Integrated CI/CD with GitHub Actions
   - Configured GitHub Actions to run `opa test` automatically on every commit.  
   - Ensures policies are always validated before deployment.  

3. Built Local Enforcement Environment
   - Enabled Kubernetes on Docker Desktop as the runtime environment.  

4. Deployed OPA Gatekeeper  
   - Installed Gatekeeper into the Kubernetes cluster to enforce compliance at admission time.  

5. Set Up ArgoCD for GitOps  
   - Connected GitHub repo to ArgoCD so policy updates sync automatically into Kubernetes.


This same approach can be extended to:  
- Access management controls  
- Encryption enforcement  
- Container image vulnerability checks  
- Data retention & lifecycle policies  
- Network and firewall compliance  

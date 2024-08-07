# Frequently Asked Questions (FAQs)

## General Questions

### 1. Why I'm not able to see the Compliace Percentage?

These are the possibilities,

    	1.	You may overlook,

    		*	The need to create a dedicated application in ComplianceCow similar to the one used in PolicyCow.

    		*	The inclusion of user inputs provided in PolicyCow.

    		*	The need to return an evidence file from the rule.

    	2.	If you're making an external call, please be aware that your firewall may have restrictions in place.

### 2. What's the connection between rules and applications?

In ComplianceCow, having an application is essential for running a rule.

### 3. How do I create an application type in ComplianceCow?

You have the option to publish the application you've already created in PolicyCow. This action will generate the application type in ComplianceCow.

### 4. What distinguishes the `input.yaml` file in the rule folder from the one in the task folder?

The `input.yaml` file within rules is utilized during rule execution. Conversely, within the task, it serves solely for testing purposes.

### 5. How can I effectively track errors encountered during rule execution?

To track errors encountered during rule execution:

You can locate a file named `cowexecutions/cowexecutions.ndjson`, which contains information about the rule execution. If you return a proper error message, you can check it there. If not, you can find the rule execution setup under `cowexecutions/rules/{{rulename}}`. Additionally, you'll find the `logs.txt` inside the rule/task folders for further insights.

### 6. Why am I unable to view suggestions when using the application module?

If you're developing the application, you'll need to install it for local testing. You can utilize the `install_cow_packages.sh` script for the installation process.

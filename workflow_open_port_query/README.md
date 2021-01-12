# Open Port Query Workflow

This workflow is used to evaluate which ports are open to a specific, untrusted zone. 

Core items include:

    * Capturing the NGfW's existing zones
    * Querying the NGFW's rulebase for rules allowing traffic from the untrusted zone
    * Outputs the results in a report
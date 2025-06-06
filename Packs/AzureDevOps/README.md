Use the Azure DevOps pack to manage Git repositories in Azure DevOps services. Microsoft Azure DevOps Server provides version control, reporting, requirements management, project management, automated builds, testing and release management capabilities. It covers the entire application lifecycle, and enables DevOps capabilities.<br>

## What does this pack do?

- Get mapping fields from a remote incident.
- Run a pipeline. A DevOps pipeline is a set of automated processes and tools that allows both developers and operations professionals to work cohesively to build and deploy code to a production environment.
- Add a user, assign the user a license and extensions, and make the user a member of a project group in an account.
- Remove the user from all project memberships.
- Create, update, or retrieve a pull request.
- Retrieve pull requests in a repository.
- Retrieve all projects in the organization that the authenticated user has access to.
- Retrieve Git repositories in the organization project.
- Query users that were added to organization projects.
- Retrieve information for a pipeline run.
- Retrieve a list of pipeline runs, project pipelines, or repository branches.

This pack contains an integration, whose main purpose is to manage Git repositories in Azure DevOps Services.<br>

<~XSIAM>

## Azure DevOps

### This pack includes

- Log Normalization - XDM mapping for key event types.

**Pay Attention:**

- This pack should only be installed after installing the Azure Logs pack.
- This pack is currently supported only for logs being sent through log-analytics.

### Supported log categories

- Licensing events.
- Extension events.
- Git events.
- Group events.
- Library events.
- Token events.
- Policy events.
- Project events.
- Release events.
- Pipelines events.
- Security events.

### Timestamp Ingestion

For *msft_azure_devops_raw*, timestamp ingestion is according to the following field:

- TimeGenerated

The timestamp is in UTC time zone YYYY-mm-ddTHH:MM:SS.ssssZ format. E.g.: 2025-02-04T11:23:29.0324070Z

</~XSIAM>

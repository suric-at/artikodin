# Artikodin

[![Articuno](https://assets.pokemon.com/assets/cms2/img/pokedex/full/144.png)](https://www.pokemon.com/us/pokedex/articuno)

## What is Artikodin?

Artikodin is a freeze manager for repositories in an organization.

When setup on a repository, on pull request create or update, it will check if the repository is currently in a freeze window:
- If yes, check if any exception request has been created
  - If yes, check if the exception request has been approved by a valid approver for that freeze window
      - If yes, put a `success` status on the pull request to allow merging
      - Else, put an `error` status on the pull request to prevent merging without an approved exception
  - Else:
    - Create an exception request in `pending` mode in the Artikodin controller repository
    - Put an `error` status on the pull request to prevent merging without asking for an exception
- Else, put a `success` status on the pull request to allow merging

> **Naming:** a `"contents" pull request` is the pull request with the actual content to merge, and `exception request` is a pull request in the controller repository that only serves for approving the exception, not the contents.

The flow of a pull request hence becomes the following:
- Open/update "contents" pull request
- The "contents" pull request gets approved by normal repository approvers (can be done in parallel of the exception process)
- If in a freeze window that matches the repository and branch:
  - The "contents" pull request gets frozen by an `error` status
  - An exception request  pull request gets open by Artikodin in the controller repository, in `pending` mode
  - The requester can comment `/exception` in the exception request pull request and provide a justification, this will assign reviewers to the pull request for approval of the exception
  - A reviewer can approve the exception request pull request
  - The approval will unfreeze the "contents" pull request with a `success` status
- The "contents" pull request can be merged

Artikodin also runs a scheduled workflow to:
- Activate freeze windows that we just entered into, updating the status of any "contents" pull request in any affected repository to prevent merging without asking for exceptions (note: this does not open exception request, even in `pending` mode, without an update to the "contents" pull request)
- Deactivate freeze windows that we just exited from, updating the status of any "contents" pull request in any affected repository to allow merging

## Where is the name coming from?

[Artikodin](https://www.pokepedia.fr/Artikodin) is the french name of [Articuno](https://www.pokemon.com/us/pokedex/articuno), a legendary bird Pokémon (144 in the Pokédex!) that can create blizzards by freezing moisture in the air.

## Reference

### GitHub App

Artikodin can work with two GitHub Apps for split permissions and better security. The two apps require the permissions as follows:

- **Artikodin controller**
  - Secrets:
    - `ARTIKODIN_CONTROLLER_APP_ID` for the GitHub application ID
    - `ARTIKODIN_CONTROLLER_PRIVATE_KEY` for the GitHub application private key
  - Scope: exceptions repository only
  - Repository permissions
    - `Contents`, read and write
      - Allows to verify existence, create and delete branches in the controller repository
    - `Metadata`, read-only
    - `Pull requests`, read and write
      - Allows to read the pull requests in the contents repositories
      - Allows to write pull requests in the controller repository

- **Artikodin protector**
  - Secrets:
    - `ARTIKODIN_CONTENTS_APP_ID` for the GitHub application ID
    - `ARTIKODIN_CONTENTS_PRIVATE_KEY` for the GitHub application private key
  - Scope: all the repositories you want to protect / global scope
  - Repository permissions
    - `Actions`, read and write
      - Allows to dispatch workflows from the `request` composite workflow
    - `Commit statuses`, read and write
      - Allows to update commit status in the contents repositories
    - `Metadata`, read-only
    - `Pull requests`, read and write
      - Allows to read the pull requests in the contents repositories
      - Allows to write pull requests in the controller repository
  - Organization permissions
    - `Members`, read-only

You can, of course, use a single GitHub application with the superset of permissions of the two listed above. This is however slightly more risky as the workflows will be able to write contents in your source code repositories.

### Protecting a repository

To protect a repository using Artikodin, copy the workflows in `templates/contents-repository-workflows/` into the `.github/workflows/` directory of the repository. You will also want to make the `freeze` status (or as configured in `controller.yaml`) as **required** in the GitHub settings for the repository.

You then just need to setup freeze window schedules.

### Configuration

To configure Artikodin, you simply need to adjust a few configuration files:
- `configuration/controller.yaml` to configure how the controller itself will behave
- `configuration/approvers.yaml` to configure the default approvers, containing a list of `Approver` objects (see below)
- `configuration/repositories.yaml` to configure the default repositories to consider in freeze windows, containing a list of `Repository` objects (see below)
- `configuration/schedules/` to configure the freeze windows, with each individual file in that directory (allows for subdirectories) containing a `FreezeWindow` object (see below)

You will also need to setup a repository in which the exception requests will be opened. You need to copy the contents of `template/exceptions-repository-workflows/` into the `.github/workflows/` directory of that repository. This is the repository for which the Artikodin controller will need access.

#### The `Approver` object

This is an object with the following parameters:

- `handle`, the GitHub handle of the approver (e.g. `xaf`)
- `reviewer`, a boolean indicating whether this reviewer should be (e.g. `true`)

If providing a simple string, it will be considered the same as if an object with just a `handle` was provided.


#### The `Repository` object

This is an object with the following parameters:
- `handle`, the repository handle (e.g. `suric-at/artikodin`)
  - This should be provided as `owner/name` but if providing only `name`, the artikodin repository owner will be assumed.
  - The `name` can contain wildcards (`*`), single-character wildcards (`?`), allowed ranges (`[...]`) and disallowed ranges (`[!...]`), as supported by [`fnmatch`](https://docs.python.org/3/library/fnmatch.html).
- `branches`, the list of branches of the repository to consider (e.g. `["main", "dev"]`); do not set or set to `null` to match all branches


#### The `FreezeWindow` object

This is an object with the following parameters:
- `id`, the unique identifier of that freeze window, this is not required as one can be generated from the rest of the information, but highly recommended (e.g. a UUID4)
- `reason`, the reason for the freeze window (e.g. `Black Friday 2023`)
- `from`, the beginning datetime of the freeze window, in ISO8601 (e.g. `2023-11-21T00:01:00-08:00`)
- `to`, the ending datetime of the freeze window, in ISO8601 (e.g. `2023-11-28T23:59:00-08:00`)
- `approvers`, a list of extra `Approver` objects specifically for that freeze window (both the default and these approvers will be considered for exceptions related to that freeze window, and default and these reviewers added to exception requests)
- `only`, a list of `Repository` objects that **overrides entirely** the default repositories; if specified, only those repositories will be considered as affected by that freeze window
- `include`, a list of extra `Repository` objects to consider with the default repositories; if specified, both the default and these repositories will be considered as affected by that freeze window
- `exclude`, a list of `Repository` objects to exclude, applies last to any combination of repositories to exclude those from being affected by that freeze window (practical when using wildcard matching)

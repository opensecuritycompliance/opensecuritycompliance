package githubconnector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
)

type AccessToken struct {
	AccessToken string `json:"accessToken" yaml:"AccessToken"`
}

type UserDefinedCredentials struct {
	AccessToken AccessToken `json:"accessToken" yaml:"AccessToken"`
}

type GitHubConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	GitHubClient           *github.Client
}

const (
	CODEOWNERS_PATH       = ".github/CODEOWNERS"
	CODEOWNERS_ERROR_PATH = "https://api.github.com/repos/%s/%s/codeowners/errors"
)

func (thisObj *GitHubConnector) Validate() (bool, error) {

	err := thisObj.ValidateGithubCredential()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (thisObj *GitHubConnector) GetGitHubCredentials() (accessToken string, err error) {

	err = thisObj.ValidateGithubCredential()
	if err != nil {
		return "", fmt.Errorf("invalid accesstoken")
	}
	gitHub := thisObj.UserDefinedCredentials.AccessToken

	accessToken = gitHub.AccessToken

	if accessToken == "" {
		return "", fmt.Errorf("accessToken is empty")
	}

	return accessToken, nil
}

func (thisObj *GitHubConnector) ValidateGithubCredential() (err error) {
	gitHub := thisObj.UserDefinedCredentials.AccessToken

	accessToken := gitHub.AccessToken

	if accessToken == "" {
		return fmt.Errorf("accessToken is empty")
	}
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	_, _, err = client.Users.Get(ctx, "")
	if err != nil {
		if strings.Contains(err.Error(), "401 Bad credentials") {
			return errors.New("Invalid AccessToken")
		}
		return err
	}
	return nil
}

func (thisObj *GitHubConnector) GetGitHubClient(authenticationType string) (*github.Client, error) {
	if thisObj.GitHubClient != nil {
		return thisObj.GitHubClient, nil
	}

	if strings.ToLower(authenticationType) == "pat" {
		accessToken, err := thisObj.GetGitHubCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve GitHub credentials: %w", err)
		}

		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
		tc := oauth2.NewClient(context.Background(), ts)
		thisObj.GitHubClient = github.NewClient(tc)
	}
	return thisObj.GitHubClient, nil
}

func (thisObj *GitHubConnector) ListRepositoriesByOrg(ctx context.Context, orgName string) ([]*github.Repository, error) {

	repos, _, err := thisObj.GitHubClient.Repositories.ListByOrg(ctx, orgName, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching repositories for organization '%s': %w", orgName, err)
	}

	return repos, nil
}

func (thisObj *GitHubConnector) GetRepository(ctx context.Context, owner, repoName string) (*github.Repository, error) {

	repo, _, err := thisObj.GitHubClient.Repositories.Get(ctx, owner, repoName)
	if err != nil {
		return nil, fmt.Errorf("error fetching repository '%s' for owner '%s': %w", repoName, owner, err)
	}

	return repo, nil
}

func (thisObj *GitHubConnector) ListBranches(ctx context.Context, owner, repoName string) ([]*github.Branch, error) {

	branches, _, err := thisObj.GitHubClient.Repositories.ListBranches(ctx, owner, repoName, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching branches for repository '%s': %w", repoName, err)
	}

	return branches, nil
}

func (thisObj *GitHubConnector) GetFileContent(ctx context.Context, owner, repoName string, ref *github.RepositoryContentGetOptions) (*github.RepositoryContent, error) {

	filePath := CODEOWNERS_PATH

	fileContent, _, _, err := thisObj.GitHubClient.Repositories.GetContents(ctx, owner, repoName, filePath, ref)
	if err != nil {
		return nil, fmt.Errorf("error fetching file content at path '%s' in repository '%s': %w", filePath, repoName, err)
	}

	return fileContent, nil
}

func (thisObj *GitHubConnector) GetBranchProtection(ctx context.Context, owner, repoName, branchName string) (*github.Protection, error) {

	protection, _, err := thisObj.GitHubClient.Repositories.GetBranchProtection(ctx, owner, repoName, branchName)
	if err != nil {
		return nil, fmt.Errorf("error fetching branch protection for branch '%s' in repository '%s': %w", branchName, repoName, err)
	}

	return protection, nil
}

func (thisObj *GitHubConnector) ListPullRequests(ctx context.Context, owner, repoName string, opts *github.PullRequestListOptions) ([]*github.PullRequest, error) {
	prs, _, err := thisObj.GitHubClient.PullRequests.List(ctx, owner, repoName, opts)
	if err != nil {
		return nil, fmt.Errorf("error fetching pull requests for repository '%s': %w", repoName, err)
	}

	return prs, nil
}

func (thisObj *GitHubConnector) GetPermissionLevel(ctx context.Context, owner, repoName, username string) (*github.RepositoryPermissionLevel, error) {

	permission, _, err := thisObj.GitHubClient.Repositories.GetPermissionLevel(ctx, owner, repoName, username)
	if err != nil {
		return nil, fmt.Errorf("error fetching permissions for user '%s' in repository '%s': %w", username, repoName, err)
	}

	return permission, nil
}

func (thisObj *GitHubConnector) GetPRReviewers(ctx context.Context, owner, repoName string, prNumber int, opts *github.ListOptions) ([]string, error) {

	reviewerLogins := make([]string, 0)

	requestedReviewers, err := thisObj.ListReviewers(ctx, owner, repoName, prNumber, opts)
	if err != nil {
		return nil, fmt.Errorf("error fetching requested reviewers for PR #%d: %w", prNumber, err)
	}

	reviews, _, err := thisObj.GitHubClient.PullRequests.ListReviews(ctx, owner, repoName, prNumber, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching reviews for PR #%d: %w", prNumber, err)
	}

	for _, reviewer := range requestedReviewers.Users {
		reviewerLogins = append(reviewerLogins, reviewer.GetLogin())
	}

	for _, review := range reviews {
		reviewerLogins = append(reviewerLogins, review.GetUser().GetLogin())
	}

	return reviewerLogins, nil
}

func (thisObj *GitHubConnector) ListReviewers(ctx context.Context, owner, repoName string, prNumber int, opts *github.ListOptions) (*github.Reviewers, error) {

	reviewers, _, err := thisObj.GitHubClient.PullRequests.ListReviewers(ctx, owner, repoName, prNumber, opts)
	if err != nil {
		return nil, fmt.Errorf("error fetching reviewers for PR #%d in repository '%s': %w", prNumber, repoName, err)
	}

	return reviewers, nil
}

func (thisObj *GitHubConnector) RemoveReviewers(ctx context.Context, owner, repoName string, prNumber int, reviewers github.ReviewersRequest) (*github.Response, error) {

	response, err := thisObj.GitHubClient.PullRequests.RemoveReviewers(ctx, owner, repoName, prNumber, reviewers)
	if err != nil {
		return nil, fmt.Errorf("error removing reviewers from PR #%d in repository '%s': %w", prNumber, repoName, err)
	}

	return response, nil
}

func (thisObj *GitHubConnector) GetBranchRules(ctx context.Context, owner, repoName, branchName string) ([]*github.RepositoryRule, error) {

	rules, _, err := thisObj.GitHubClient.Repositories.GetRulesForBranch(ctx, owner, repoName, branchName)
	if err != nil {
		return nil, fmt.Errorf("error fetching rules for branch '%s' in repository '%s': %w", branchName, repoName, err)
	}

	return rules, nil
}

func (thisObj *GitHubConnector) CreateBranchRuleSet(ctx context.Context, owner, repoName string, ruleSet github.Ruleset) (*github.Ruleset, error) {

	createdRuleSet, _, err := thisObj.GitHubClient.Repositories.CreateRuleset(ctx, owner, repoName, &ruleSet)
	if err != nil {
		return nil, fmt.Errorf("error creating ruleset for repository '%s': %w", repoName, err)
	}

	return createdRuleSet, nil
}

func (thisObj *GitHubConnector) RequestReviewersForPR(ctx context.Context, owner, repoName string, prNumber int, reviewers github.ReviewersRequest) (*github.PullRequest, error) {

	pr, _, err := thisObj.GitHubClient.PullRequests.RequestReviewers(ctx, owner, repoName, prNumber, reviewers)
	if err != nil {
		return nil, fmt.Errorf("error requesting reviewers for PR #%d in repository '%s': %w", prNumber, repoName, err)
	}

	return pr, nil
}

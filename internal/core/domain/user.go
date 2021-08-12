package domain

// User information extracted from token authentication
type User struct {
	Id string `json:"id,omitempty"`
	// User screen name, used for login
	Username string `json:"username,omitempty"`
	// User real name
	Name string `json:"name,omitempty"`
	// Optional url of the user display image
	Picture string `json:"picture,omitempty"`
	// For RBAC operations
	Role string `json:"role,omitempty"`
	// The OAuth2 provider used by this user
	Provider string `json:"provider,omitempty"`
	// The identifier connection this user with the OAuth provider
	TokenID string `json:"tokenID,omitempty"`
}

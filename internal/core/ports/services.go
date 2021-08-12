package ports

import (
	"github.com/sy-software/minerva-shield/internal/core/domain"
)

// ProxyService applies validations and sends request to a destination server
type ProxyService interface {
	// Authorize checks if a request is authorized to access a resource
	Authorize(request domain.Request) (domain.Request, error)
}

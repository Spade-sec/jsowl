package jsowl

import "github.com/youmulijiang/jsowl/internal/model"

type Result = model.Result
type Issue = model.Issue
type Resource = model.Resource
type Endpoint = model.Endpoint
type Finding = model.Finding
type Statistics = model.Statistics
type BrowserStatus = model.BrowserStatus
type ResourceType = model.ResourceType

const (
	ResourceTypeDocument = model.ResourceTypeDocument
	ResourceTypeScript   = model.ResourceTypeScript
	ResourceTypeChunk    = model.ResourceTypeChunk
	ResourceTypeAPI      = model.ResourceTypeAPI
	ResourceTypeRoute    = model.ResourceTypeRoute
	ResourceTypeAsset    = model.ResourceTypeAsset
	ResourceTypeExternal = model.ResourceTypeExternal
)

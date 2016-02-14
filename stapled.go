package stapled

import (
	"net/http"
)

type stapled struct {
	c *cache

	httpSrv *http.Server
}

package wordpress

import (
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

const (
	catalogerName        = "wordpress-plugins-cataloger"
	wordpressPluginsGlob = "**/wp-content/plugins/*/*.php"
)

func NewWordpressPluginCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseWordpressPluginFiles, wordpressPluginsGlob)
}

package graphql

import (
	"sync"

	gql "github.com/graphql-go/graphql"
)

// baseLocale is the locale the package-level Schema is built for. Per-request
// localized schemas are built on demand by schemaForLocale.
const baseLocale = "en"

// initSchemaFunc is used for testing — allows injecting errors
var initSchemaFunc = initSchemaImpl

// schemaMu guards schemaCache.
var schemaMu sync.RWMutex

// schemaCache holds one built schema per locale. graphql-go bakes descriptions
// into the type system at build time, so a localized schema is a separate
// build; caching keeps that cost to once per locale.
var schemaCache = map[string]gql.Schema{}

// InitSchema initializes the GraphQL schema
func InitSchema() error {
	return initSchemaFunc()
}

// initSchemaImpl builds the base-locale schema and publishes it as Schema.
func initSchemaImpl() error {
	s, err := buildSchema(baseLocale)
	if err != nil {
		return err
	}
	Schema = s
	schemaMu.Lock()
	schemaCache[baseLocale] = s
	schemaMu.Unlock()
	return nil
}

// schemaForLocale returns the schema whose descriptions are rendered in lang,
// building and caching it on first use. It falls back to the base-locale
// Schema when the localized build fails, so a query is never dropped over a
// translation problem.
func schemaForLocale(lang string) gql.Schema {
	if lang == "" {
		return Schema
	}

	schemaMu.RLock()
	cached, ok := schemaCache[lang]
	schemaMu.RUnlock()
	if ok {
		return cached
	}

	s, err := buildSchema(lang)
	if err != nil {
		return Schema
	}

	schemaMu.Lock()
	schemaCache[lang] = s
	schemaMu.Unlock()
	return s
}

// buildSchema builds the GraphQL type system and schema per AI.md PART 14,
// with every description resolved for lang. The type system mirrors the REST
// API field for field so both interfaces expose identical functionality.
func buildSchema(lang string) (gql.Schema, error) {
	// Define the UserAgent type
	userAgentType := gql.NewObject(gql.ObjectConfig{
		Name:        "UserAgent",
		Description: tr(lang, "graphql.types.UserAgent.description"),
		Fields: gql.Fields{
			"product": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.UserAgent.fields.product"),
			},
			"version": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.UserAgent.fields.version"),
			},
			"rawValue": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.UserAgent.fields.rawValue"),
			},
		},
	})

	// Define the IPResponse type
	ipResponseType := gql.NewObject(gql.ObjectConfig{
		Name:        "IPResponse",
		Description: tr(lang, "graphql.types.IPResponse.description"),
		Fields: gql.Fields{
			"ip": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.ip"),
			},
			"ipDecimal": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.ipDecimal"),
			},
			"country": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.country"),
			},
			"countryIso": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.countryIso"),
			},
			"countryEu": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.IPResponse.fields.countryEu"),
			},
			"regionName": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.regionName"),
			},
			"regionCode": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.regionCode"),
			},
			"metroCode": &gql.Field{
				Type:        gql.Int,
				Description: tr(lang, "graphql.types.IPResponse.fields.metroCode"),
			},
			"zipCode": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.zipCode"),
			},
			"city": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.city"),
			},
			"latitude": &gql.Field{
				Type:        gql.Float,
				Description: tr(lang, "graphql.types.IPResponse.fields.latitude"),
			},
			"longitude": &gql.Field{
				Type:        gql.Float,
				Description: tr(lang, "graphql.types.IPResponse.fields.longitude"),
			},
			"timezone": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.timezone"),
			},
			"asn": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.asn"),
			},
			"asnOrg": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.asnOrg"),
			},
			"hostname": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.IPResponse.fields.hostname"),
			},
			"userAgent": &gql.Field{
				Type:        userAgentType,
				Description: tr(lang, "graphql.types.IPResponse.fields.userAgent"),
			},
			"isVpn": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.IPResponse.fields.isVpn"),
			},
			"isProxy": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.IPResponse.fields.isProxy"),
			},
			"isTor": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.IPResponse.fields.isTor"),
			},
		},
	})

	// Define the PortResponse type
	portResponseType := gql.NewObject(gql.ObjectConfig{
		Name:        "PortResponse",
		Description: tr(lang, "graphql.types.PortResponse.description"),
		Fields: gql.Fields{
			"ip": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.PortResponse.fields.ip"),
			},
			"port": &gql.Field{
				Type:        gql.Int,
				Description: tr(lang, "graphql.types.PortResponse.fields.port"),
			},
			"reachable": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.PortResponse.fields.reachable"),
			},
		},
	})

	projectInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "ProjectInfo",
		Description: tr(lang, "graphql.types.ProjectInfo.description"),
		Fields: gql.Fields{
			"name": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ProjectInfo.fields.name"),
			},
			"tagline": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ProjectInfo.fields.tagline"),
			},
			"description": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ProjectInfo.fields.description"),
			},
		},
	})

	buildInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "BuildInfo",
		Description: tr(lang, "graphql.types.BuildInfo.description"),
		Fields: gql.Fields{
			"commit": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.BuildInfo.fields.commit"),
			},
			"date": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.BuildInfo.fields.date"),
			},
		},
	})

	torInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "TorInfo",
		Description: tr(lang, "graphql.types.TorInfo.description"),
		Fields: gql.Fields{
			"enabled": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.TorInfo.fields.enabled"),
			},
			"running": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.TorInfo.fields.running"),
			},
			"status": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.TorInfo.fields.status"),
			},
			"hostname": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.TorInfo.fields.hostname"),
			},
		},
	})

	i2pInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "I2PInfo",
		Description: tr(lang, "graphql.types.I2PInfo.description"),
		Fields: gql.Fields{
			"enabled": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.I2PInfo.fields.enabled"),
			},
			"running": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.I2PInfo.fields.running"),
			},
			"status": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.I2PInfo.fields.status"),
			},
			"hostname": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.I2PInfo.fields.hostname"),
			},
			"provider": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.I2PInfo.fields.provider"),
			},
		},
	})

	featuresInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "FeaturesInfo",
		Description: tr(lang, "graphql.types.FeaturesInfo.description"),
		Fields: gql.Fields{
			"tor": &gql.Field{
				Type:        torInfoType,
				Description: tr(lang, "graphql.types.FeaturesInfo.fields.tor"),
			},
			"i2p": &gql.Field{
				Type:        i2pInfoType,
				Description: tr(lang, "graphql.types.FeaturesInfo.fields.i2p"),
			},
			"geoip": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.FeaturesInfo.fields.geoip"),
			},
		},
	})

	checksInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "ChecksInfo",
		Description: tr(lang, "graphql.types.ChecksInfo.description"),
		Fields: gql.Fields{
			"database": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ChecksInfo.fields.database"),
			},
			"cache": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ChecksInfo.fields.cache"),
			},
			"disk": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ChecksInfo.fields.disk"),
			},
			"scheduler": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ChecksInfo.fields.scheduler"),
			},
			"tor": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ChecksInfo.fields.tor"),
			},
			"i2p": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.ChecksInfo.fields.i2p"),
			},
		},
	})

	statsInfoType := gql.NewObject(gql.ObjectConfig{
		Name:        "StatsInfo",
		Description: tr(lang, "graphql.types.StatsInfo.description"),
		Fields: gql.Fields{
			"requestsTotal": &gql.Field{
				Type:        gql.Int,
				Description: tr(lang, "graphql.types.StatsInfo.fields.requestsTotal"),
			},
			"requests24h": &gql.Field{
				Type:        gql.Int,
				Description: tr(lang, "graphql.types.StatsInfo.fields.requests24h"),
			},
			"activeConnections": &gql.Field{
				Type:        gql.Int,
				Description: tr(lang, "graphql.types.StatsInfo.fields.activeConns"),
			},
		},
	})

	// Define the HealthResponse type — mirrors model.HealthResponse field for
	// field so GraphQL health is functionally equivalent to REST health.
	healthResponseType := gql.NewObject(gql.ObjectConfig{
		Name:        "HealthResponse",
		Description: tr(lang, "graphql.types.HealthResponse.description"),
		Fields: gql.Fields{
			"project": &gql.Field{
				Type:        projectInfoType,
				Description: tr(lang, "graphql.types.HealthResponse.fields.project"),
			},
			"status": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.HealthResponse.fields.status"),
			},
			"pendingRestart": &gql.Field{
				Type:        gql.Boolean,
				Description: tr(lang, "graphql.types.HealthResponse.fields.pendingRestart"),
			},
			"restartReason": &gql.Field{
				Type:        gql.NewList(gql.String),
				Description: tr(lang, "graphql.types.HealthResponse.fields.restartReason"),
			},
			"version": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.HealthResponse.fields.version"),
			},
			"goVersion": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.HealthResponse.fields.goVersion"),
			},
			"build": &gql.Field{
				Type:        buildInfoType,
				Description: tr(lang, "graphql.types.HealthResponse.fields.build"),
			},
			"uptime": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.HealthResponse.fields.uptime"),
			},
			"mode": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.HealthResponse.fields.mode"),
			},
			"timestamp": &gql.Field{
				Type:        gql.String,
				Description: tr(lang, "graphql.types.HealthResponse.fields.timestamp"),
			},
			"features": &gql.Field{
				Type:        featuresInfoType,
				Description: tr(lang, "graphql.types.HealthResponse.fields.features"),
			},
			"checks": &gql.Field{
				Type:        checksInfoType,
				Description: tr(lang, "graphql.types.HealthResponse.fields.checks"),
			},
			"stats": &gql.Field{
				Type:        statsInfoType,
				Description: tr(lang, "graphql.types.HealthResponse.fields.stats"),
			},
		},
	})

	// Define the root query
	rootQuery := gql.NewObject(gql.ObjectConfig{
		Name: "Query",
		Fields: gql.Fields{
			"myIP": &gql.Field{
				Type:        ipResponseType,
				Description: tr(lang, "graphql.query.myIP.description"),
				Resolve:     resolveMyIP,
			},
			"lookupIP": &gql.Field{
				Type:        ipResponseType,
				Description: tr(lang, "graphql.query.lookupIP.description"),
				Args: gql.FieldConfigArgument{
					"ip": &gql.ArgumentConfig{
						Type:        gql.NewNonNull(gql.String),
						Description: tr(lang, "graphql.args.lookupIP.ip"),
					},
				},
				Resolve: resolveLookupIP,
			},
			"checkPort": &gql.Field{
				Type:        portResponseType,
				Description: tr(lang, "graphql.query.checkPort.description"),
				Args: gql.FieldConfigArgument{
					"port": &gql.ArgumentConfig{
						Type:        gql.NewNonNull(gql.Int),
						Description: tr(lang, "graphql.args.checkPort.port"),
					},
				},
				Resolve: resolveCheckPort,
			},
			"health": &gql.Field{
				Type:        healthResponseType,
				Description: tr(lang, "graphql.query.health.description"),
				Resolve:     resolveHealth,
			},
		},
	})

	return gql.NewSchema(gql.SchemaConfig{
		Query: rootQuery,
	})
}

package oauth

import (
	"context"
	"crypto/tls"
	"github.com/gin-gonic/gin"
	mysql "github.com/go-oauth2/mysql/v4"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	v4redis "github.com/go-oauth2/redis/v4"
	redis "github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql" //导入mysql驱动
	"github.com/tianlin0/go-plat-oauth/oauth/ginserver"
	"github.com/tianlin0/go-plat-startupcfg/startupcfg"
	"github.com/tianlin0/go-plat-utils/conv"
	"github.com/tianlin0/go-plat-utils/utils/httputil"
	"log"
	"net/http"
)

/*

oauth.StartGinOAuthServer(router, oauth.OauthConfig)


授权码模式（authorization code）
1、http://localhost:8083/oauth2/authorize?grant_type=authorization_code&scope=aaaa&client_id=aaaa&
response_type=code&redirect_uri=http://localhost/aaa
2、http://localhost/aaa?code=PKGBRPYUOWK_IRJIWXHPNA
3、http://localhost:8083/oauth2/token?grant_type=authorization_code&scope=aaaa&client_id=aaaa&
client_secret=827ccb0eea8a706c4c34a16891f84e7b&code=PKGBRPYUOWK_IRJIWXHPNA&redirect_uri=http://localhost/aaa
{
    "access_token": "UCIXDWWKNGAGAOTCNS_KVW",
    "expires_in": 7200,
    "refresh_token": "K0F-4RK-UCCZBOAR7RMM4G",
    "scope": "insert_from",
    "token_type": "Bearer"
}

简化模式（implicit）
不需要第三方服务器
如果用户登录获取是通过别的code方式获取到的话，则用下面方式,此code为rtx登录以后返回的code
1、http://localhost:8083/oauth2/authorize?grant_type=authorization_code&scope=plat_ulink&client_id=plat_ulink&
response_type=token&redirect_uri=http://localhost/aaa&code=xxxxxxxxxxxxx
注意，这里response_type=token
无需传递client secret，传递client_id只是为了验证在auth server配置的redirect_uri是否一致
redirect_uri中如果携带参数，则最好对url编码再作为参数传递过去
2、http://localhost/aaa#access_token=UQWIF1Y0NP2_LXFYF55JUQ&expires_in=3600&scope=plat_ulink&token_type=Bearer


客户端模式（client credentials）(主要用于api认证，跟用户无关)
1、http://localhost:8083/oauth2/token?grant_type=client_credentials&client_id=aaaa&
client_secret=827ccb0eea8a706c4c34a16891f84e7b&scope=aaaa
{
    "access_token": "BK7MO2DEMIE3SV9WRBVHJG",
    "expires_in": 7200,
    "scope": "aaaa",
    "token_type": "Bearer"
}
2、接口访问
http://localhost:8083/oauth2/read
Authorization: Bearer BK7MO2DEMIE3SV9WRBVHJG
{
    "ClientID": "000000",
    "UserID": "",
    "RedirectURI": "",
    "Scope": "insert_from",
    "Code": "",
    "CodeCreateAt": "0001-01-01T00:00:00Z",
    "CodeExpiresIn": 0,
    "Access": "VR37N7MKO2UX6M0VHIJVAA",
    "AccessCreateAt": "2021-03-10T15:17:15.419168+08:00",
    "AccessExpiresIn": 7200000000000,
    "Refresh": "",
    "RefreshCreateAt": "0001-01-01T00:00:00Z",
    "RefreshExpiresIn": 0
}


刷新token消息
http://localhost:8083/oauth2/token?grant_type=refresh_token&client_id=aaaa&
client_secret=827ccb0eea8a706c4c34a16891f84e7b&scope=aaaa&refresh_token=6S3C0HQZVJWAETDLA5OMLQ
说明：token被刷新以后，前面的token就用不了了
*/

// GinOauthOption oauth配置
type GinOauthOption struct {
	RouteFrontPath               string                              //路径的前缀，比如需要加上/v1/等等
	ClientStore                  oauth2.ClientStore                  //client存储在mysql中 必传
	UserAuthorizationHandler     server.UserAuthorizationHandler     //获取用户的信息的接口 必传
	PasswordAuthorizationHandler server.PasswordAuthorizationHandler //如果用用户密码登录的话，则需要验证用户的密码是否正确
	TokenStoreConnect            startupcfg.Database                 //token存储在的连接，redis twemproxy 代理不支持multi会报错
	//可以通过 Extend 包含 keyNamespace，useTLS 来设置redis的特殊配置
	ClientAuthorizedHandler server.ClientAuthorizedHandler //是否允许该客户端使用authorization_code或 __implicit 功能，
	// 如果不设置，则会使用ClientScopeHandler对scope范围进行判断
	ClientScopeHandler           server.ClientScopeHandler                                  //客户端传进来的scope是否正确的判断
	AuthorizeScopeHandler        server.AuthorizeScopeHandler                               //User传进来的scope是否正确的判断
	ExtensionFieldsHandler       server.ExtensionFieldsHandler                              //返回token信息时，可扩展展示一些信息，比如用户名
	TokenManager                 *manage.Manager                                            //authorization management token的管理
	TokenCreateHandler           func(ctx context.Context, tokenMap map[string]interface{}) //TokenCreateHandler token创建时后
	TokenCreateNumber            int                                                        //TokenCreateNumber 一个账号生成的token数量
	TokenVerifySkipper           func(*gin.Context) oauth2.TokenInfo                        //HandleTokenVerify read方法里验证token是否跳过检查
	ErrorHandleFunc              ginserver.ErrorHandleFunc                                  //HandleTokenVerify 如果验证出错的话，怎么处理, 默认全局处理
	DefaultAuthorizeCodeTokenCfg *manage.Config                                             //token过期时间的默认设置
	DefaultPasswordTokenCfg      *manage.Config                                             //根据用户密码生成的用户的token过期时间默认设置
	DefaultClientTokenCfg        *manage.Config                                             //设置Client过期时间和refreash，
	// RefreshTokenExp，0表示不过期，IsGenerateRefresh 是否生成刷新token
	ReadUserCallbackHandler func(ctx *gin.Context, token oauth2.TokenInfo) interface{} //read个人信息时，对个人信息进行特殊处理后输出
}

func initGinOAuthServer(oauthConfig *GinOauthOption) *server.Server {
	manager := manage.NewDefaultManager()

	if oauthConfig.TokenManager != nil {
		manager = oauthConfig.TokenManager
	}

	isSetRedis := false

	if oauthConfig.TokenStoreConnect != nil {
		if oauthConfig.TokenStoreConnect.DriverName() == string(startupcfg.DriverRedis) {
			storeTemp, err := getStoreByRedis(oauthConfig)
			if err == nil {
				isSetRedis = true
				manager.MapTokenStorage(storeTemp)
			}
		} else if oauthConfig.TokenStoreConnect.DriverName() == string(startupcfg.DriverMysql) {
			dsn := oauthConfig.TokenStoreConnect.DatasourceName()
			mysqlStore := mysql.NewDefaultStore(
				mysql.NewConfig(dsn),
			)
			isSetRedis = true
			manager.MapTokenStorage(mysqlStore)
		}
	}

	if !isSetRedis {
		storyDefault, err := store.NewMemoryTokenStore()
		if err != nil {
			//log.Error(err)
			return nil
		}
		manager.MapTokenStorage(storyDefault)
	}

	//用户列表的查询方式
	manager.MapClientStorage(oauthConfig.ClientStore)

	return initServers(manager, oauthConfig)
}

func getStoreByRedis(oauthConfig *GinOauthOption) (*v4redis.TokenStore, error) {
	db, _ := conv.Int64(oauthConfig.TokenStoreConnect.DatabaseName())
	dbInt := int(db)

	redisOpts := &redis.Options{
		Addr:     oauthConfig.TokenStoreConnect.ServerAddress(),
		Password: oauthConfig.TokenStoreConnect.Password(),
		DB:       dbInt,
	}

	if oauthConfig.TokenStoreConnect.User() != "" {
		redisOpts.Username = oauthConfig.TokenStoreConnect.User()
	}

	if oauthConfig.TokenStoreConnect.Extend != nil {
		if useTLS, ok := oauthConfig.TokenStoreConnect.Extend("useTLS"); ok {
			if useTLSBool, ok := useTLS.(bool); ok {
				if useTLSBool {
					var tlsConfig = &tls.Config{InsecureSkipVerify: false}
					tlsConfig.MinVersion = tls.VersionTLS12
					redisOpts.TLSConfig = tlsConfig
				}
			}
		}
	}

	keyNamespace := "{default-oauth}" //默认值
	if oauthConfig.TokenStoreConnect.Extend != nil {
		if useKeyName, ok := oauthConfig.TokenStoreConnect.Extend("keyNameSpace"); ok {
			if useKeyNameString, ok := useKeyName.(string); ok {
				if useKeyNameString != "" {
					keyNamespace = useKeyNameString
				}
			}
		}
	}

	reClient := redis.NewClient(redisOpts)
	pong, err := reClient.Ping(context.Background()).Result()
	log.Println("redis ping:", pong, err)
	if err == nil {
		// 处理分片的问题
		return v4redis.NewRedisStore(redisOpts, keyNamespace), nil
	}

	//redis连接失败
	log.Println("oauthConfig.Conn nil:redis连接失败", err)

	return nil, err
}

func initServers(manager *manage.Manager, oauthConfig *GinOauthOption) *server.Server {
	// Initialize the oauth2 service
	servers := ginserver.InitServer(manager)
	ginserver.SetAllowGetAccessRequest(true)
	ginserver.SetClientInfoHandler(server.ClientFormHandler)
	ginserver.SetUserAuthorizationHandler(oauthConfig.UserAuthorizationHandler)
	ginserver.SetPasswordAuthorizationHandler(oauthConfig.PasswordAuthorizationHandler)
	if oauthConfig.ClientScopeHandler != nil {
		ginserver.SetClientScopeHandler(oauthConfig.ClientScopeHandler)
	}
	if oauthConfig.AuthorizeScopeHandler != nil {
		ginserver.SetAuthorizeScopeHandler(oauthConfig.AuthorizeScopeHandler)
	}
	if oauthConfig.ExtensionFieldsHandler != nil {
		ginserver.SetExtensionFieldsHandler(oauthConfig.ExtensionFieldsHandler)
	}
	if oauthConfig.ErrorHandleFunc != nil {
		ginserver.DefaultConfig.ErrorHandleFunc = oauthConfig.ErrorHandleFunc
	}
	if oauthConfig.DefaultAuthorizeCodeTokenCfg != nil {
		manage.DefaultAuthorizeCodeTokenCfg = oauthConfig.DefaultAuthorizeCodeTokenCfg
	}
	if oauthConfig.DefaultClientTokenCfg != nil {
		manage.DefaultClientTokenCfg = oauthConfig.DefaultClientTokenCfg
	} else {
		//如果为空的话，默认为authorcode模式，方便后端对token进行刷新操作
		manage.DefaultClientTokenCfg = manage.DefaultAuthorizeCodeTokenCfg
	}
	if oauthConfig.DefaultPasswordTokenCfg != nil {
		manage.DefaultPasswordTokenCfg = oauthConfig.DefaultPasswordTokenCfg
	}

	{ //对过期时间进行批量处理，不能为永久，解决redis内存不断高升的问题
		if manage.DefaultAuthorizeCodeTokenCfg.AccessTokenExp > ginserver.DefaultCacheAccessTokenMaxExpiresIn ||
			manage.DefaultAuthorizeCodeTokenCfg.AccessTokenExp == 0 {
			manage.DefaultAuthorizeCodeTokenCfg.AccessTokenExp = ginserver.DefaultCacheAccessTokenMaxExpiresIn
		}
		if manage.DefaultAuthorizeCodeTokenCfg.RefreshTokenExp > ginserver.DefaultCacheAccessTokenMaxExpiresIn ||
			manage.DefaultAuthorizeCodeTokenCfg.RefreshTokenExp == 0 {
			manage.DefaultAuthorizeCodeTokenCfg.RefreshTokenExp = ginserver.DefaultCacheAccessTokenMaxExpiresIn
		}
		if manage.DefaultClientTokenCfg.AccessTokenExp > ginserver.DefaultCacheAccessTokenMaxExpiresIn ||
			manage.DefaultClientTokenCfg.AccessTokenExp == 0 {
			manage.DefaultClientTokenCfg.AccessTokenExp = ginserver.DefaultCacheAccessTokenMaxExpiresIn
		}
		if manage.DefaultClientTokenCfg.RefreshTokenExp > ginserver.DefaultCacheAccessTokenMaxExpiresIn ||
			manage.DefaultClientTokenCfg.RefreshTokenExp == 0 {
			manage.DefaultClientTokenCfg.RefreshTokenExp = ginserver.DefaultCacheAccessTokenMaxExpiresIn
		}
	}
	return servers
}

// StartGinOAuthServer 启动一个gin框架的oauth服务
func StartGinOAuthServer(oauthRoot *gin.RouterGroup, oauthConfig *GinOauthOption) bool {
	if oauthConfig == nil {
		return false
	}
	if oauthConfig.ClientStore == nil {
		return false
	}

	serverTemp := initGinOAuthServer(oauthConfig)
	if serverTemp == nil {
		return false
	}

	auth := oauthRoot.Group("/oauth2")
	{
		auth.GET("/authorize", func(c *gin.Context) {
			//logs.CtxLogger(c.Request.Context()).Debug("authorize get start:", c.Request.Header)
			ginserver.HandleAuthorizeRequest(c)
		})
		auth.POST("/authorize", func(c *gin.Context) {
			//logs.CtxLogger(c.Request.Context()).Debug("authorize post start:", c.Request.Header)
			ginserver.HandleAuthorizeRequest(c)
		}) //如果有内容比较多的情况时，不方便用GET

		// application/x-www-form-urlencoded
		// grant_type=authorization_code&code=YJKXOTK0NDCTYJFJYY0ZZJJILWFLNZMTMWUYNJRHNJQZNZHI&client_id=odp-external&
		//client_secret=827f0a65-48b3-11eb-b993-8e2d46a782b1&
		//redirect_uri=http%3A%2F%2Flocalhost%2Fswagger%2Foauth2-redirect.html
		var tokenHandle = func(c *gin.Context) {
			//loggers := logs.CtxLogger(c.Request.Context())

			//loggers.Debug("token start:", c.Request.Header)

			if oauthConfig.TokenCreateNumber > 0 {
				ginserver.HandleTokenNumberRequest(c, oauthConfig.TokenCreateNumber, oauthConfig.TokenCreateHandler)
			} else {
				ginserver.HandleTokenRequest(c, oauthConfig.TokenCreateHandler)
			}

			//loggers.Debug("token end", c.Writer)
		}

		//生成token的方法
		auth.GET("/token", tokenHandle)
		//auth.POST("/token", tokenHandle)
		//验证并获取登录用户信息
		middleHandle := getMiddleTokenVerifyHandle(oauthConfig)

		auth.GET("/read", middleHandle, func(c *gin.Context) {
			ti, exists := c.Get(ginserver.DefaultConfig.TokenKey)
			if exists {
				resp := &httputil.CommResponse{
					Data: ti,
				}
				if oauthConfig.ReadUserCallbackHandler != nil {
					token, ok := ti.(oauth2.TokenInfo)
					if ok {
						tokenInfo := oauthConfig.ReadUserCallbackHandler(c, token)
						resp.Data = tokenInfo
					}
				}
				if resp.Data != nil {
					_ = httputil.WriteCommResponse(c.Writer, resp)
					return
				}
			}
			_ = httputil.WriteCommResponse(c.Writer, &httputil.CommResponse{
				Code:    http.StatusUnauthorized,
				Message: http.StatusText(http.StatusUnauthorized),
			})
		})
	}
	return true
}

func getMiddleTokenVerifyHandle(oauthConfig *GinOauthOption) gin.HandlerFunc {
	//验证并获取登录用户信息
	middleHandle := ginserver.Config{}
	if oauthConfig.ErrorHandleFunc != nil {
		middleHandle.ErrorHandleFunc = oauthConfig.ErrorHandleFunc
	} else {
		// 默认的错误输出方式
		middleHandle.ErrorHandleFunc = func(c *gin.Context, e error) {
			//loggers := logs.CtxLogger(c.Request.Context())

			//loggers.Error("middleHandle.ErrorHandleFunc error:", e)
			//loggers.Error(c.Request.Header, c.Request.RequestURI)
			errMsg := http.StatusText(http.StatusUnauthorized)
			if e != nil {
				errMsg = e.Error()
			}
			_ = httputil.WriteCommResponse(c.Writer, &httputil.CommResponse{
				Code:    http.StatusUnauthorized,
				Message: errMsg,
			})
			c.Abort()
		}
	}

	if oauthConfig.TokenVerifySkipper != nil {
		middleHandle.Skipper = func(c *gin.Context) bool {
			tokenInfo := oauthConfig.TokenVerifySkipper(c)
			if tokenInfo != nil {
				c.Set(ginserver.DefaultConfig.TokenKey, tokenInfo)
				return true
			}
			return false
		}
	}

	return ginserver.HandleTokenVerify(middleHandle)
}

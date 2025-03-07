package oauth

import (
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	oredis "github.com/go-oauth2/redis/v4"
	"github.com/go-redis/redis/v8"
	"log"
)

// getOauthServer initOAUTH 初始化时，token存储到redis中，客户端存储到mysql中
func getOauthServer(redisOpt *redis.Options, clientStore oauth2.ClientStore) *server.Server {
	manager := getOauthManager(redisOpt, clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("internal error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("response error:", re.Error.Error())
		return
	})
	return srv
}

// getOauthManager 获取
func getOauthManager(redisOpt *redis.Options, clientStore oauth2.ClientStore) oauth2.Manager {
	manager := manage.NewDefaultManager()
	if redisOpt == nil || redisOpt.Addr == "" {
		// token memory store
		manager.MustTokenStorage(store.NewMemoryTokenStore())
	} else {
		manager.MapTokenStorage(oredis.NewRedisStore(redisOpt))
	}

	//用户列表的查询方式
	manager.MapClientStorage(clientStore)
	return manager
}

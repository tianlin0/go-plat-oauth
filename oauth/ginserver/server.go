package ginserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
	gCache "github.com/patrickmn/go-cache"
	"github.com/tianlin0/go-plat-utils/crypto"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	oauthServer                         *server.Server
	once                                sync.Once
	cacheAccessTokenMinSecond           = 10 * time.Minute   //10分钟以内的话，则不缓存了
	DefaultCacheAccessTokenMaxExpiresIn = time.Hour * 24 * 7 //token存储最长时间：7天过期时间
	accessTokenCache                    = gCache.New(DefaultCacheAccessTokenMaxExpiresIn, 30*time.Minute)
)

//var createAccessTokenMap = cache.NewMapCache(&cache.MapCache{
//	CacheType:         "CreateOauthAccessToken",
//	MaxLen:            5,
//	FlushTimeInterval: 30 * time.Minute, //30分钟重新更新一次
//	FlushCallback: func(dataEntry *cache.DataEntry, isAllEmpty bool, willDeleted bool) bool {
//		if isAllEmpty || dataEntry == nil {
//			return true
//		}
//		if tokenDataList, ok := dataEntry.Value.([]oauth2.TokenInfo); ok {
//			if len(tokenDataList) == 0 {
//				return true
//			}
//
//			newTokenAllInfoList := make([]oauth2.TokenInfo, 0)
//			for _, oneToken := range tokenDataList {
//				if oneToken == nil {
//					continue
//				}
//				oneToken = getNewTokenInfo(oneToken)
//				if oneToken != nil {
//					newTokenAllInfoList = append(newTokenAllInfoList, oneToken)
//				}
//			}
//
//			if len(newTokenAllInfoList) == 0 {
//				return true
//			}
//
//			newCreateAccessTokenMap := cache.NewMapCache(&cache.MapCache{
//				CacheType: dataEntry.Type,
//			})
//			newCreateAccessTokenMap.Set(dataEntry.Key, newTokenAllInfoList,
//				time.Duration(DefaultCacheAccessTokenMaxExpiresIn.Seconds())*time.Second)
//			return false
//		}
//		return true
//	},
//})

// InitServer Initialize the service
func InitServer(manager oauth2.Manager) *server.Server {
	once.Do(func() {
		oauthServer = server.NewDefaultServer(manager)
	})
	return oauthServer
}

// HandleAuthorizeRequest the authorization request handling
func HandleAuthorizeRequest(c *gin.Context) {
	err := oauthServer.HandleAuthorizeRequest(c.Writer, c.Request)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	c.Abort()
}

// HandleTokenRequest token request handling
func HandleTokenRequest(c *gin.Context, tokenHandler func(ctx context.Context, tokenMap map[string]interface{})) {
	err := handleTokenRequest(oauthServer, c.Writer, c.Request, tokenHandler)
	if err != nil {
		log.Println("HandleTokenRequest error:", err)
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	log.Println("HandleTokenRequest Abort!")

	c.Abort()
}

func handleTokenRequest(s *server.Server, w http.ResponseWriter, r *http.Request, tokenHandler func(ctx context.Context, tokenMap map[string]interface{})) error {
	ctx := r.Context()

	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		return tokenError(ctx, s, w, err)
	}

	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return tokenError(ctx, s, w, err)
	}
	tokenData := oauthServer.GetTokenData(ti)

	if tokenHandler != nil {
		tokenHandler(ctx, tokenData)
	}

	log.Println("GetAccessToken-getTokenData: ", tokenData)

	return token(ctx, s, w, tokenData, nil)
}

// HandleTokenNumberRequest token request handling
func HandleTokenNumberRequest(c *gin.Context, number int, tokenHandler func(ctx context.Context, tokenMap map[string]interface{})) {
	// 缓存中最多生成10个token备份，而且需要检查是否过期
	if number > 10 || number <= 0 {
		number = 10
	}

	r := c.Request
	ctx := r.Context()
	// 检查请求参数是否合法
	gt, tgr, err := oauthServer.ValidationTokenRequest(r)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	// 默认为7天
	tokenCacheSecond := int(DefaultCacheAccessTokenMaxExpiresIn.Seconds())
	tokenCacheKey := ""
	{
		tokenCacheKey = fmt.Sprintf("{%s|%s|%s|%s|%s|%s|%s|%s|%s}",
			tgr.ClientID,
			tgr.ClientSecret,
			tgr.UserID,
			tgr.Scope,
			tgr.Code,
			tgr.CodeChallenge,
			tgr.CodeChallengeMethod,
			tgr.Refresh,
			tgr.CodeVerifier)
		tokenCacheKey = crypto.Md5(tokenCacheKey)
	}

	//log.Debug("HandleTokenNumberRequest:", number, tokenCacheKey)

	tokenAllInfoList := make([]oauth2.TokenInfo, 0)

	// 从本地缓存获取
	tokenAllInfo, ok := accessTokenCache.Get(tokenCacheKey)
	if ok {
		if tokenList, ok := tokenAllInfo.([]oauth2.TokenInfo); ok {
			tokenAllInfoList = tokenList
		}
	}

	//缓存里已经存在，则检查是否含有可用的token，避免redis重复生成
	if len(tokenAllInfoList) >= number {
		newTokenList, cacheUpdate := getTokenListFromCache(ctx, tokenAllInfoList)
		if cacheUpdate {
			setAllTokenInfoToCache(newTokenList, tokenCacheKey, tokenCacheSecond)
		}

		if len(newTokenList) > 0 {
			_ = token(c.Request.Context(), oauthServer, c.Writer, oauthServer.GetTokenData(newTokenList[0]), nil)
			return
		}
	}

	ti, err := oauthServer.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		//如果有错，则用缓存中存在的
		newTokenList, cacheUpdate := getTokenListFromCache(ctx, tokenAllInfoList)
		if cacheUpdate {
			setAllTokenInfoToCache(newTokenList, tokenCacheKey, tokenCacheSecond)
		}
		if len(newTokenList) > 0 {
			_ = token(c.Request.Context(), oauthServer, c.Writer, oauthServer.GetTokenData(newTokenList[0]), nil)
			return
		}

		//有可能是因为redis等没有存起来的缘故
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	tokenAllInfoList = append(tokenAllInfoList, ti)
	setAllTokenInfoToCache(tokenAllInfoList, tokenCacheKey, tokenCacheSecond)

	tokenData := oauthServer.GetTokenData(ti)
	if tokenHandler != nil {
		tokenHandler(ctx, tokenData)
	}

	_ = token(c.Request.Context(), oauthServer, c.Writer, tokenData, nil)
	return
}

func getTokenListFromCache(ctx context.Context, tokenAllInfoList []oauth2.TokenInfo) ([]oauth2.TokenInfo, bool) {
	newTokenAllInfoList := make([]oauth2.TokenInfo, 0)

	if tokenAllInfoList == nil || len(tokenAllInfoList) == 0 {
		return newTokenAllInfoList, false
	}

	cacheUpdate := false
	for _, oneToken := range tokenAllInfoList {
		if oneToken == nil {
			cacheUpdate = true
			continue
		}
		//直接去判断redis中token是否在有效期内
		tiTemp, err := oauthServer.Manager.LoadAccessToken(ctx, oneToken.GetAccess())
		if err != nil || tiTemp == nil {
			cacheUpdate = true
			continue
		}

		//需要改变expires的过期时间，因为有变化
		{ //更新accessToken的过期时间，当新增的token创建时间返回
			tiTemp = getNewTokenInfo(tiTemp)
			if tiTemp == nil {
				cacheUpdate = true
				continue
			}
		}

		if tiTemp != nil {
			newTokenAllInfoList = append(newTokenAllInfoList, tiTemp)
		}
	}
	return newTokenAllInfoList, cacheUpdate
}

func setAllTokenInfoToCache(tokenAllInfoList []oauth2.TokenInfo, tokenCacheKey string, tokenCacheSecond int) {
	newTokenAllInfoList := make([]oauth2.TokenInfo, 0)
	for i, oneToken := range tokenAllInfoList {
		if oneToken != nil {
			newTokenAllInfoList = append(newTokenAllInfoList, tokenAllInfoList[i])
		}
	}
	accessTokenCache.Set(tokenCacheKey, newTokenAllInfoList, time.Duration(tokenCacheSecond)*time.Second)
}

func getNewTokenInfo(tiTemp oauth2.TokenInfo) oauth2.TokenInfo {
	if tiTemp == nil {
		return nil
	}
	oldCreateAt := tiTemp.GetAccessCreateAt()
	oldExpiresIn := tiTemp.GetAccessExpiresIn()

	{ //检查一下这个token是否过期
		newExpiresIn := oldExpiresIn - cacheAccessTokenMinSecond //减少10分钟进行判断
		now := time.Now()
		expiresTime := oldCreateAt.Add(newExpiresIn)
		if !(now.After(oldCreateAt) && now.Before(expiresTime)) {
			return nil
		}
	}

	oldRefreshCreateAt := tiTemp.GetRefreshCreateAt()
	oldRefreshExpiresIn := tiTemp.GetRefreshExpiresIn()

	{ // 如果合法，则更新创建时间
		newCreateAt := time.Now()
		tiTemp.SetAccessCreateAt(newCreateAt)
		tiTemp.SetRefreshCreateAt(newCreateAt)

		expiresTime := oldCreateAt.Add(oldExpiresIn)
		newExpiresIn := expiresTime.Sub(newCreateAt)
		tiTemp.SetAccessExpiresIn(newExpiresIn)

		expiresRefreshTime := oldRefreshCreateAt.Add(oldRefreshExpiresIn)
		newRefreshExpiresIn := expiresRefreshTime.Sub(newCreateAt)
		tiTemp.SetRefreshExpiresIn(newRefreshExpiresIn)
	}

	return tiTemp
}

func tokenError(ctx context.Context, s *server.Server, w http.ResponseWriter, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return token(ctx, s, w, data, header, statusCode)
}

func token(ctx context.Context, s *server.Server, w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
	//loggers := logs.CtxLogger(ctx)
	//loggers.Info("token:", data, "\n")

	if fn := s.ResponseTokenHandler; fn != nil {
		return fn(w, data, header, statusCode...)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

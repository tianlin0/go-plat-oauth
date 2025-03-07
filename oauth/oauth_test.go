package oauth_test

import (
	"testing"
)

//func TestOauthServer(t *testing.T) {
//    ginOpt := &framework.GinOption{}
//    ginOpt.OauthConfig = &GinOauthOption{}
//    ginOpt.OauthConfig.TokenCreateNumber = 1  //设置每个账号创建token的数量
//    ginOpt.OauthConfig.RouteFrontPath = "/v1" //请求地址的前缀设置
//    ginOpt.OauthConfig.DefaultAuthorizeCodeTokenCfg = manage.DefaultAuthorizeCodeTokenCfg
//    ginOpt.OauthConfig.TokenVerifySkipper = func(ctx *gin.Context) bool { //传入的token进行检查
//        //如果是数据库里存在的话，就跳过检查，直接返回
//        headers := param.GetAllHeaders(ctx.Request)
//        authStr, ok := headers["authorization"]
//        if !ok {
//            return false
//        }
//
//        // authorization 格式正确
//        authList := strings.Split(authStr, " ")
//        if len(authList) != 2 {
//            return false
//        }
//
//        return false
//    }
//    //read 接口利用token获取用户信息时额外增加另外的属性
//    ginOpt.OauthConfig.ExtensionFieldsHandler = func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{}) {
//        logs.DefaultLogger().Debug("ExtensionFieldsHandler")
//
//        clientId := ti.GetClientID()
//        userId := ti.GetUserID()
//        if userId == "" {
//            userId = clientId
//        }
//
//        logs.DefaultLogger().Debug("ExtensionFieldsHandler:", clientId, userId)
//
//        return nil
//    }
//
//    framework.InitGinContainer(ginOpt, func(router *gin.Engine) error {
//
//        return nil
//    })
//}

func TestCommUrl(t *testing.T) {

}

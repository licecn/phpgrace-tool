<?php
/**
 * web 微信扫码登录
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2018 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tools
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
class webWxLogin{

    //微信开放平台对应 appid
    private $appid  = '******';
    //微信开放平台对应 secret
    private $secret = '******';
    //回调地址 [ 注意 : 与微信开放平台设置域名匹配 ]
    private $redirect_uri = 'http://www.xxx.com/xxx/';
    //token 及相关数据记录
    private $tokens;
    //openid
    public $openId;

    /*
     * 获取用户信息
     * 返回数组形式的用户信息 :
     * {"openid":"**","nickname":"*","sex":1,...,"headimgurl":"...","privilege":[],"unionid":"..."}
     */
    public function getUserinfo(){
        $this->getAccessToken();
        $url = "https://api.weixin.qq.com/sns/userinfo?access_token=0055&openid={$this->tokens['openid']}";
        $res = $this->curlGet($url);
        $res .= '';
        $arr = json_decode($res, true);
        if(!empty($arr['errcode'])){exit('数据错误请返回重试');}
        return $arr;
    }

    //获取access_token
    public function getAccessToken(){
        $url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid='.$this->appid.
            '&secret='.$this->secret.'&code='.$_GET['code'].'&grant_type=authorization_code';
        $res = $this->curlGet($url);
        $res .= '';
        $this->tokens = json_decode($res, true);
        if(!empty($this->tokens['errcode'])){exit('数据错误请返回重试');}
        $this->openId = $this->tokens['openid'];
        removeSession('wxLoginState');
    }

    public function login(){
        setSession('wxLoginState', uniqid());
        $url = 'https://open.weixin.qq.com/connect/qrconnect?appid='.$this->appid.'&redirect_uri='.
            urlencode($this->redirect_uri).'&response_type=code&scope=snsapi_login&state='.
            $_SESSION['wxLoginState'].'#wechat_redirect';
        header('location:'.$url);
        exit;
    }

    public function curlGet($url){
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        return curl_exec($curl);
    }
}
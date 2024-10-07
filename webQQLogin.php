<?php
/**
 * curl
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2018 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tools
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class webQQLogin{
	//appId
	private $appId       = '';
	//appKey
	private $appKey      = '';
	//code 认证后返回的安全码
	private $code;
	//返回url
	private $redirectUri = 'http://您的域名/qqLogin/back';
	//授权列表 多个使用逗号隔开
	private $scope   = 'getUserInfo';
	//获取Access Token
	public  $AccessToken;
	//openId
	public $openId;
	//错误代码
	public $error;
	
	public function __construct(){
		if(empty($this->appId) || empty($this->appId)){exit('请先配置 appid 和 appKey');}
	}
	
	public function getOpenId(){
		//获取token
		$this->getAccessToken();
		$url  = 'https://graph.qq.com/oauth2.0/me?access_token='.$this->AccessToken['access_token'];
		$res  = $this->qqCurl($url);
		if(strpos($res, "callback") !== false){
			$arr = $this->getCallBacks($res);
			$this->openId = $arr['openid'];
		}else{
			exit('获取openId失败，请返回重试！');
		}
	}
	
	//获取用户信息
	public function getUserInfo(){
		$this->getOpenId();
		$url = 'https://graph.qq.com/user/get_user_info';
		$data   = array(); 
		$data[] = 'oauth_consumer_key='.$this->appId;
		$data[] = 'access_token='.$this->AccessToken['access_token'];
		$data[] = 'openid='.$this->openId;
		$url    = $url.'?'.implode('&', $data);
		$res    = $this->qqCurl($url);
		$msg    = json_decode($res, true);
		if($msg['ret'] != 0){
			exit('用户信息获取失败，请返回重试！');
		}
		return $msg;
	}
	
	//解析callback
	private function getCallBacks($str){
		$lpos = strpos($str, "(");
        $rpos = strrpos($str, ")");
        $str  = substr($str, $lpos + 1, $rpos - $lpos -1);
        return json_decode($str, true);
	}
	
	//通过Authorization Code获取Access Token
	public function getAccessToken(){
		$url    = 'https://graph.qq.com/oauth2.0/token';
		$data   = array(); 
		$data[] = 'grant_type=authorization_code';
		$data[] = 'client_id='.$this->appId;
		$data[] = 'client_secret='.$this->appKey;
		$data[] = 'code='.$this->code;
		$data[] = 'redirect_uri='.$this->redirectUri;
		$url    = $url.'?'.implode('&', $data);
		$res    = $this->qqCurl($url);
		if(is_integer(strpos($res, 'access_token'))){
			parse_str($res, $this->AccessToken);
		}else{
			exit('获取 AccessToken 失败，请返回重试');
		}
	}
	
	public function qqCurl($url){
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
		return curl_exec($curl);
	}
	
	public function checkBack(){
		if(empty($_GET['state'])){$_GET['state'] = '';}
		if(empty($_GET['code'])){exit('登录信息错误，请返回重试！');}
		if($_SESSION['qqLoginSta'] != $_GET['state']){
			exit('登录信息错误，请返回重试！');
		}
		//注销 $_SESSION['qqLoginSta'] 防止刷新
		removeSession('qqLoginSta');
		$this->code = $_GET['code'];
		return true;
	}
	
	public function login(){
		$url = 'https://graph.qq.com/oauth2.0/authorize';
		$data   = array();
		$data[] = 'response_type=code';
		$data[] = 'client_id='.$this->appId;
		$data[] = 'redirect_uri='.$this->redirectUri;
		//-------生成唯一随机串防CSRF攻击
		$state = 'gracecms_'.md5(uniqid());
		setSession('qqLoginSta', $state);
		$data[] = 'state='.$state;
		$data[] = 'scope='.$this->scope;
		$url = $url.'?'.implode('&', $data);
		header('location:'.$url);
		exit();
	}
}

<?php
/*
 * graceWechat - 微信开发支持类
 * 作者 : 深海 5213606@qq.com
 * 版本 v 1.0.2
 * 官网 : http://www.phpgrace.com/wechat
 */
//公众号开发配置
define('GWECHAT_APPID',       '******');        //公众号appId
define('GWECHAT_APPSECRET',   '******');        //公众号APPSECRET
define('GWECHAT_VALIDTOKEN',  'gracetest');        //Token 用于接口认证

//微信支付[ 公众号内支付 ] 需要的配置
define('GWECHAT_WXPAY_APPID',  '******'); //公众号appId 与 微信支付对应
define('GWECHAT_WXPAY_MCHID',  '******');       //微信支付对应的商户ID
define('GWECHAT_WXPAY_KEY',    '******'); //微信支付对应的KEY

//扫码支付配置
define('GWECHAT_WXPAY_SCAN_APPID',  '******'); //公众号appId 与 微信支付对应
define('GWECHAT_WXPAY_SCAN_MCHID',  '******');       //微信支付对应的商户ID
define('GWECHAT_WXPAY_SCAN_KEY',    '******'); //微信支付对应的KEY

//APP支付配置
define('GWECHAT_WXPAY_APP_APPID',  '******'); //appId 在腾讯开发者中心获取
define('GWECHAT_WXPAY_APP_MCHID',  '******');       //微信支付对应的商户ID
define('GWECHAT_WXPAY_APP_KEY',    '******'); //微信支付对应的KEY

//小程序支付配置
define('GWECHAT_WXPAY_XCX_APPID',  '******'); //小程序 appId 与 微信支付对应
define('GWECHAT_WXPAY_XCX_MCHID',  '******');       //微信支付对应的商户ID
define('GWECHAT_WXPAY_XCX_KEY',    '******'); //微信支付对应的KEY

//小程序获取用户信息的必须配置
define('GWECHAT_XCX_APPID',  '******'); //小程序 appId 与 微信支付对应
define('GWECHAT_XCX_SECRET', '******'); //小程序对应的 SECRET

//运行日志跟踪
define('GWECHAT_LOG',        'true'); //是否记录微信交互数据

class graceWeChat{
	public  $appId;                       //公众号 appId
	public  $appsecret;                   //公众号 appsecret
	public  $validToken;                  //Token 用于接口认证
	public  $openId;                      //客户openid
	public  $ourOpenId;                   //公众号openid
	public  $msg;                         //消息对象
	public  $msgType;                     //消息类型
	public  $msgContent;                  //消息内容
	public  $event;                       //具体事件
	private $accessTokenFile;             //access token 文件路径
	public  $accessToken;                 //access token
	public  $error;                       //错误信息
	
	public function __construct(){
		$this->accessTokenFile = './accessTokenFile.php';
		$this->appId           = GWECHAT_APPID;
		$this->appsecret       = GWECHAT_APPSECRET;
		$this->validToken      = GWECHAT_VALIDTOKEN;
	}
	
	public function codeToUser($code){
		$url = 'https://api.weixin.qq.com/sns/jscode2session?appid='.GWECHAT_XCX_APPID
				.'&secret='.GWECHAT_XCX_SECRET.'&js_code='.$code.'&grant_type=authorization_code';
		$res = $this->curlGet($url);
		return json_decode($res, true);
	}
	
	public function arrayToXml($arr){
		$xml = '<xml>';
		foreach($arr as $key => $val){
			if (is_numeric($val)){
    			$xml.="<".$key.">".$val."</".$key.">";
    		}else{
    			$xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
    		}
		}
		$xml .= '</xml>';
		return $xml;
	}
	
	//xml转数组函数
	public function xmlToArray($xml){
        libxml_disable_entity_loader(true);
        $arr = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);		
		return $arr;
	}
	
	//微信支付 - 统一下单接口
	public function createOrder($order, $type = 'JSAPI'){
		switch($type){
			case 'JSAPI' :
				$order['appid']              = GWECHAT_WXPAY_APPID;
				$order['mch_id']             = GWECHAT_WXPAY_MCHID;
			break;
			case 'NATIVE' :
				$order['appid']              = GWECHAT_WXPAY_SCAN_APPID;
				$order['mch_id']             = GWECHAT_WXPAY_SCAN_MCHID;
			break;
			case 'APP' :
				$order['appid']              = GWECHAT_WXPAY_APP_APPID;
				$order['mch_id']             = GWECHAT_WXPAY_APP_MCHID;
			break;
			case 'XCX' :
				$order['appid']              = GWECHAT_WXPAY_XCX_APPID;
				$order['mch_id']             = GWECHAT_WXPAY_XCX_MCHID;
			break;
		}
		
		$order['nonce_str']          = uniqid();
		$order['spbill_create_ip']   = $this->getIp();
		if($type == 'XCX'){
			$order['trade_type']         = 'JSAPI';
		}else{
			$order['trade_type']         = $type;
		}
		$order['sign']               = $this->sign($order, $type);
		$xml = $this->arrayToXml($order);
		$url = 'https://api.mch.weixin.qq.com/pay/unifiedorder';
		$res = $this->curlPost($url, $xml);
		$arr = $this->xmlToArray($res);
		if($arr['return_code'] == 'FAIL'){exit(json_encode(array('status' =>'error', 'msg'=>$arr['return_msg'])));}
		if($arr['result_code'] == 'FAIL'){exit(json_encode(array('status' =>'error', 'msg'=>$arr['err_code_des'])));}
		if($type == 'NATIVE'){return $arr;}
		//返回前端所需的支付数据
		$arrPay                     = array();
		if($type == 'APP'){
			$arrPay['appid']            = $order['appid'];
			$arrPay['noncestr']         = uniqid();
			$arrPay['package']	        = 'Sign=WXPay';
			$arrPay['partnerid']        = $order['mch_id'];
			$arrPay['prepayid']         = $arr['prepay_id'];
			$arrPay['timestamp']        = time();
			$sign = $this->sign($arrPay, $type);
			$arrPay['sign']             = $sign;
			exit(json_encode($arrPay));
		}
		$arrPay['appId']            = $order['appid'];
		$arrPay['timeStamp']        = time().'';
		$arrPay['nonceStr']         = uniqid();
		$arrPay['package']          = "prepay_id=".$arr['prepay_id'];
		$arrPay['signType']         = "MD5";
		$arrPay['paySign']          = $this->sign($arrPay, $type);
		$arrPay['status']           ='yes';
		//扫码支付生成二维码
		exit(json_encode($arrPay));
	}
	
	//异步验证接口
	public function payBack($type = 'JSAPI'){
		if(PHP_VERSION >= 5.6){
			$data = file_get_contents("php://input");
		}else{
			$data = $GLOBALS["HTTP_RAW_POST_DATA"];
		}
		if(empty($data)){$this->jsonMsg(array('status' => 'error', 'msg' => '数据为空'));}
	    libxml_disable_entity_loader(true);
	    $msg = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOCDATA);
		if($msg->result_code != 'SUCCESS'){$this->jsonMsg(array('status' => 'error', 'msg' => '数据为空'));}
		//查询订单
		$res      = $this->getOrder($msg->transaction_id, $type);
		$order    = $this->xmlToArray($res);
		if($order['result_code'] != 'SUCCESS'){$this->jsonMsg(array('status' => 'error', 'msg' => '订单状态错误'));}
		if($order['trade_state'] != 'SUCCESS'){$this->jsonMsg(array('status' => 'error', 'msg' => '订单状态错误'));}
		return $order;
	}
	
	public function getOrder($transaction_id, $type = 'JSAPI'){
		$url = 'https://api.mch.weixin.qq.com/pay/orderquery';
		$array = array();
		switch($type){
			case 'JSAPI' :
				$array['appid']              = GWECHAT_WXPAY_APPID;
				$array['mch_id']             = GWECHAT_WXPAY_MCHID;
			break;
			case 'NATIVE' :
				$array['appid']              = GWECHAT_WXPAY_SCAN_APPID;
				$array['mch_id']             = GWECHAT_WXPAY_SCAN_MCHID;
			break;
			case 'APP' :
				$array['appid']              = GWECHAT_WXPAY_APP_APPID;
				$array['mch_id']             = GWECHAT_WXPAY_APP_MCHID;
			break;
			case 'XCX' :
				$array['appid']              = GWECHAT_WXPAY_XCX_APPID;
				$array['mch_id']             = GWECHAT_WXPAY_XCX_MCHID;
			break;
		}
		$array['transaction_id']         = $transaction_id;
		$array['nonce_str']              = md5(uniqid());
		$array['sign']                   = $this->sign($array);
		$xml = $this->arrayToXml($array);
		$res = $this->curlPost($url, $xml);
		return $res;
	}
	
	public function sign($array, $type = 'JSAPI'){
		ksort($array);
		$string = '';
		foreach ($array as $k => $v){
			if($k != "sign" && $v != "" && !is_array($v)){$string .= $k . "=" . $v . "&";}
		}
		$string = trim($string, "&");
		switch($type){
			case 'JSAPI' :
				$string = $string . "&key=".GWECHAT_WXPAY_KEY;
			break;
			case 'NATIVE' :
				$string = $string . "&key=".GWECHAT_WXPAY_SCAN_KEY;
			break;
			case 'APP' :
				$string = $string . "&key=".GWECHAT_WXPAY_APP_KEY;
			break;
			case 'XCX' :
				$string = $string . "&key=".GWECHAT_WXPAY_XCX_KEY;
			break;
		}
		$string = md5($string);
		$result = strtoupper($string);
		return $result;
	}
	
	//短连接生成
	public function makeLink($link){
		$this->getAccessToken();
		$url  = 'https://api.weixin.qq.com/cgi-bin/shorturl?access_token='.$this->accessToken;
		$data = array(
			'action'   => 'long2short',
			'long_url' => $link
		);
		$res = $this->curlPost($url, json_encode($data));
		$urlData = json_decode($res, true);
		if(!empty($urlData['short_url'])){return $urlData['short_url'];}
		return false;
	}
	
	//上传临时素材
	public function uploadMedia($mediaFile, $type = 'image'){
		$mediaFile = realpath($mediaFile);
		if(!file_exists($mediaFile)){$this->jsonMsg(array('status' => 'error', 'msg' => '本地文件不存在'));}
		$miniType = mime_content_type($mediaFile);
		$this->getAccessToken();
		$url    = 'https://api.weixin.qq.com/cgi-bin/media/upload?access_token='.$this->accessToken.'&type='.$type;
		$data   = array('media' => '@'.$mediaFile);
		if(class_exists('CurlFile')){
			$media = new CurlFile($mediaFile);
			$media->setMimeType($miniType);
			$data  = array('media' => $media);
		}
		$res    = json_decode($this->curlPost($url, $data), true);
		if(!empty($res['errcode']) && $res['errcode'] == '40001'){
			$this->resetAccessToken();
			return $this->uploadMedia($mediaFile, $type);
		}else{
			if(empty($res) || empty($res['media_id'])){return false;}
			return $res['media_id'];
		}
	}
	
	//下载临时素材
	public function downloadMedia($mediaId, $saveFileName){
		$this->getAccessToken();
		$url = 'https://api.weixin.qq.com/cgi-bin/media/get?access_token='.$this->accessToken.'&media_id='.$mediaId;
		//测试 downlaod
		$res = $this->curlGet($url);
		if(!empty($res['errcode']) && $res['errcode'] == '40001'){
			$this->resetAccessToken();
			return $this->downloadMedia($mediaId, $saveFileName);
		}else{
			file_put_contents($saveFileName, $res);
			return $saveFileName;
		}
	}
	
	//生成二维码
	public function makeQrcode($data, $fileNmae, $expire = 2592000){
		$this->getAccessToken();
		$url = 'https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token='.$this->accessToken;
		if($expire == 'allTime'){
			$postData = array(
				'action_name' => 'QR_LIMIT_SCENE',
				'action_info' => array(
					'scene' => $data
				)
			);
			if(!empty($data['scene_str'])){$postData['action_name'] = 'QR_LIMIT_STR_SCENE';}
		}else{
			$postData = array(
				'action_name'    => 'QR_SCENE',
				'expire_seconds' => $expire,
				'action_info' => array(
					'scene' => $data
				)
			);
		}
		$res = $this->curlPost($url, json_encode($postData));
		$qrcode = json_decode($res, true);
		if(empty($qrcode['ticket'])){$this->jsonMsg(array('status' => 'error', 'msg' => '二维码创建失败'));}
		$url = 'https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket='.$qrcode['ticket'];
		$res = $this->curlGet($url);
		if(!empty($res['errcode']) && $res['errcode'] == '40001'){
			$this->resetAccessToken();
			return $this->makeQrcode($data, $fileNmae, $expire);
		}else{
			file_put_contents($fileNmae.'.png', $res);
			return $fileNmae.'.png';
		}
	}
	
	//获取jsapi_ticket用于网页开发
	public function getJsTicket(){
		$this->getAccessToken();
		$url = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token='.$this->accessToken.'&type=jsapi';
		$res = $this->curlGet($url);
		$res = json_decode($res, true);
		if(!empty($res['errcode']) && $res['errcode'] == '40001'){
			$this->resetAccessToken();
			return $this->getJsTicket();
		}else{
			$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
	    	$url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
	    	$timestamp = time();
	    	$nonceStr = $this->createNonceStr();
			$string = "jsapi_ticket={$res['ticket']}&noncestr=$nonceStr&timestamp=$timestamp&url=$url";
			$signature = sha1($string);
			$signPackage = array(
				"appId"     => $this->appId,
				"nonceStr"  => $nonceStr,
				"timestamp" => $timestamp,
				"url"       => $url,
				"signature" => $signature,
				"rawString" => $string
			);
			return $signPackage;
		}
	}
	
	private function createNonceStr($length = 16) {
		$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		$str = "";
		for ($i = 0; $i < $length; $i++){$str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);}
		return $str;
	}
	
	//发送模板消息
	public function templateMsg($msg){
		$this->getAccessToken();
		$url  = 'https://api.weixin.qq.com/cgi-bin/message/template/send?access_token='.$this->accessToken;
		$res  = $this->curlPost($url, $msg);
		$res .= '';
		return $res;
	}
	
	//创建自定义菜单
	public function createMenu($menu){
		$this->getAccessToken();
		$url = 'https://api.weixin.qq.com/cgi-bin/menu/create?access_token='.$this->accessToken;
		$res = $this->curlPost($url, $menu);
		echo $res;
	}
	
	//获取自定义菜单
	public function getMenu(){
		$this->getAccessToken();
		$url = 'https://api.weixin.qq.com/cgi-bin/get_current_selfmenu_info?access_token='.$this->accessToken;
		$res = $this->curlGet($url);
		echo $res;
	}
	
	//获取用户信息
	public function getUser($openId = null){
		if($openId == null){$openId = $this->openId;}
		$this->getAccessToken();
		$url = 'https://api.weixin.qq.com/cgi-bin/user/info?access_token='.$this->accessToken.'&openid='.$openId.'&lang=zh_CN';
		$res = $this->curlGet($url);
		$res .= '';
		if(empty($res)){return false;}
		$user = json_decode($res, true);
		if(!empty($user['errcode'])){$this->error = $res; return false;}
		if(empty($user) || empty($user['openid'])){return false;}
		//过滤昵称特殊字符
		if($user['subscribe'] != 0){
			$user['nickname'] = $this->filterName($user['nickname']);
			if(empty($user['nickname'])){$user['nickname'] = '微信用户';}
		}
		return $user;
	}
	
	public function filterName($str) { 
        $str = preg_replace('/\xEE[\x80-\xBF][\x80-\xBF]|\xEF[\x81-\x83][\x80-\xBF]/', '', $str);
        $str = preg_replace('/xE0[x80-x9F][x80-xBF]‘.‘|xED[xA0-xBF][x80-xBF]/S','?', $str);
		$str = str_replace(' ', '', $str);
        return $str;
	}
	
	public function getUserList($NEXT_OPENID = ''){
		$this->getAccessToken();
		$url ='https://api.weixin.qq.com/cgi-bin/user/get?access_token='.$this->accessToken.'&next_openid='.$NEXT_OPENID;
		return $this->curlGet($url);
	}
	
	//获取微信服务器IP
	public function getWxIp(){
	    $this->getAccessToken();
	    $url = 'https://api.weixin.qq.com/cgi-bin/getcallbackip?access_token='.$this->accessToken;
	    return $this->curlGet($url);
	}
	
	//重置  access token
	public function resetAccessToken(){
		$str = "<?php return array('access_token' => '...', 'expires_date' => 100);?>";
		file_put_contents($this->accessTokenFile, $str);
	}
	
	//获取access_token
	public function getAccessToken(){
		if(!file_exists($this->accessTokenFile)){
			$accessToken = array('expires_date' => 0);
		}else{
			$accessToken = require($this->accessTokenFile);
		}
		if(time() > $accessToken['expires_date'] + 7100){
			$url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appId='.$this->appId.'&secret='.$this->appsecret;
			$res = $this->curlGet($url); $res .= '';
			if(empty($res)){$this->jsonMsg(array('status' => 'error', 'msg' => '获取 Access Token 失败'));}
			$arr = json_decode($res, true);
			if(!empty($arr['errcode'])){$this->jsonMsg(array('status' => 'error', 'msg' => '获取Token失败 : '.$arr['errmsg']));} 
			$str = "<?php return array('access_token' => '".$arr['access_token']."', 'expires_date' => ".time().");?>";
			file_put_contents($this->accessTokenFile, $str);
			$accessToken = require($this->accessTokenFile);
		}
		$this->accessToken = $accessToken['access_token'];
		return $accessToken['access_token'];
	}
	
	//跳转至微信登录界面
	public function wxLogin($backUrl){
		session_start();
		$_SESSION['wxLoginState'] = uniqid();
		session_write_close();
		$url     = 'https://open.weixin.qq.com/connect/oauth2/authorize?appId='.
					$this->appId.
					'&redirect_uri='.urlencode($backUrl).
					'&response_type=code&scope=snsapi_userinfo&state='.$_SESSION['wxLoginState'].'#wechat_redirect';
		header('location:'.$url);
		exit();
	}
	//获取用户授权Token
	public function wxLoginBack(){
		$url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appId='.$this->appId.
				'&secret='.$this->appsecret.'&code='.$_GET['code'].
				'&grant_type=authorization_code';
		$res = $this->curlGet($url);
		$res .= '';
		$user = json_decode($res, true);
		return $user;
	}
	
	//回复文本消息
	public function reTextMsg($msg){
		$xml = '<xml><ToUserName><![CDATA['.$this->openId.']]></ToUserName><FromUserName><![CDATA['.$this->ourOpenId.']]></FromUserName><CreateTime>'.time().'</CreateTime>
<MsgType><![CDATA[text]]></MsgType><Content><![CDATA['.$msg.']]></Content></xml>';
    	echo $xml;
	}
	
	/* 回复图文消息
	 * $msg格式
	 * $msg = array(
	 * 	array('项目标题', '描述', '图片地址', '点击项目打开的Url'),
	 * 	array('项目标题', '描述', '图片地址', '点击项目打开的Url')......
	 * );
	 */
	public function reItemMsg($msg){
	    $xml = '<xml>
	    			<ToUserName><![CDATA['.$this->openId.']]></ToUserName>
	    			<FromUserName><![CDATA['.$this->ourOpenId.']]></FromUserName>
	    			<CreateTime>'.time().'</CreateTime>
	    			<MsgType><![CDATA[news]]></MsgType>
	    			<ArticleCount>'.count($msg).'</ArticleCount><Articles>';
	    foreach($msg as $val){
			$xml .= '<item>
						<Title><![CDATA['.$val[0].']]></Title>
						<Description><![CDATA['.$val[1].']]></Description>
						<PicUrl><![CDATA['.$val[2].']]></PicUrl>
						<Url><![CDATA['.$val[3].']]></Url>
					</item>';
	    }
	    $xml .= '</Articles></xml>';
	    echo $xml;
	}
	
	/*
	 * 消息接收并解析接口
	 * 注意 : php 需要配置 always_populate_raw_post_data = -1
	 */
	public function getMsg(){
		if(PHP_VERSION >= 5.6){
			$data = file_get_contents("php://input");
		}else{
			$data = $GLOBALS["HTTP_RAW_POST_DATA"];
		}
		if(empty($data)){$this->jsonMsg(array('status' => 'error', 'msg' => '数据为空'));}
	    libxml_disable_entity_loader(true);
	    $this->msg        = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOCDATA);
	    $this->openId     = $this->msg->FromUserName;
	    $this->ourOpenId  = $this->msg->ToUserName;
	    $this->msgType    = $this->msg->MsgType;
		$this->msgContent = $this->msg->Content;
		$this->event      = $this->msg->Event;
		if(GWECHAT_LOG){$this->msgLog();}
	}
	
	//json 消息输出函数
	public function jsonMsg($array){exit(json_encode($array));}
	
	//接口地址认证检查
	public function valid(){
		if(empty($_GET["timestamp"]) || empty($_GET["nonce"])){exit;}
		$tmpArr  = array($this->validToken, $_GET["timestamp"], $_GET["nonce"]);
		sort($tmpArr, SORT_STRING);
		$tmpStr  = sha1(implode($tmpArr));
		if($tmpStr == $_GET["signature"]){exit($_GET["echostr"]);}
		exit('接口消息验证错误');
	}
	
	//日志记录
	public function msgLog(){
		$str = '<html>
				<head>
				<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
				</head>
				<body>';
		$str .= "时间: ".date('Y-m-d H:i:s').'<br />微信原始数据：'.json_encode($this->msg);
		$str .= '<br />解析后的数据：<br />';
		foreach($this->msg as $k => $v){$str .= "{$k} : {$v}<br />";}
		$str .= '</body></html>';
		file_put_contents('log.html', $str);
	}
	
	/*
	 * curl GET 方式
	 * 参数1 $url
	 * 参数2 $data 格式 array('name'=>'test', 'age' => 18)
	 */
	public function curlGet($url){
	    $ch = curl_init();
	    curl_setopt($ch, CURLOPT_URL, $url);
	    curl_setopt($ch, CURLOPT_RETURNTRANSFER , true);
	    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER , false);
	    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST , false);
	    curl_setopt($ch, CURLOPT_ENCODING       , 'gzip,deflate');
	    $res  = curl_exec($ch);
	    curl_close($ch);
	    return $res;
	}
	
	/*
	 * curl POST 方式
	 * 参数1 $url
	 * 参数2 $data 格式 array('name'=>'test', 'age' => 18)
	 */
	public function curlPost($url, $data){
	    $ch = curl_init();
	    curl_setopt($ch, CURLOPT_URL, $url);
	    curl_setopt($ch, CURLOPT_RETURNTRANSFER , true);
	    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER , false);
	    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST , false);
	    curl_setopt($ch, CURLOPT_POST           , 1);
	    curl_setopt($ch, CURLOPT_POSTFIELDS     , $data);
	    curl_setopt($ch, CURLOPT_ENCODING       , 'gzip,deflate');
	    $res  = curl_exec($ch);
	    curl_close($ch);
	    return $res;
	}
	
	public function getIp() {
		if(isset($_SERVER)){
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
                $arr = explode(',',$_SERVER['HTTP_X_FORWARDED_FOR']);
                foreach ($arr as $ip){
                    $ip = trim($ip);
                    if ($ip != 'unknown'){$realip = $ip; break;}
                }
            }elseif(isset($_SERVER['HTTP_CLIENT_IP'])){
                $realip = $_SERVER['HTTP_CLIENT_IP'];
            }else{
                if (isset($_SERVER['REMOTE_ADDR'])){
                    $realip = $_SERVER['REMOTE_ADDR'];
                }else{
                    $realip = '0.0.0.0';
                }
            }
        }else{
            if (getenv('HTTP_X_FORWARDED_FOR')){
                $realip = getenv('HTTP_X_FORWARDED_FOR');
            }elseif (getenv('HTTP_CLIENT_IP')){
                $realip = getenv('HTTP_CLIENT_IP');
            }else{
                $realip = getenv('REMOTE_ADDR');
            }
        }
        preg_match("/[\d\.]{7,15}/",$realip,$onlineip);
        $realip = !empty($onlineip[0]) ? $onlineip[0] : '0.0.0.0';
        return $realip;
	}
}
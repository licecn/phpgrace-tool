<?php
/**
 * 图片处理类
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2015 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tools
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 * bmp 的处理速度很慢建议避免
 */
namespace phpGrace\tools;
class image{
	//图像资源
    private $img;
	//图像信息，包括width,height,mime 等
    private $info;
	//文件扩展名
	private $exeName;
	//图片操作对象
	private $imgObj;
	//支持的图片类型
	private $allowType = array('image/gif', 'image/jpeg', 'image/png' ,'image/x-ms-bmp');
	//水印位置
	const LT =   1 ; //标识左上角水印
    const TC =   2 ; //标识上居中水印
    const RT =   3 ; //标识右上角水印
    const LC =   4 ; //标识左居中水印
    const CC =   5 ; //标识居中水印
    const RC =   6 ; //标识右居中水印
    const LB =   7 ; //标识左下角水印
    const BC =   8 ; //标识下居中水印
    const RB =   9 ; //标识右下角水印
    //缩略规则
    const TB1 =  1 ; //常量，标识缩略图等比例缩放类型
    const TB2 =  2 ; //常量，标识缩略图缩放后填充类型
    const TB3 =  3 ; //常量，标识缩略图居中裁剪类型
    const TB4 =  4 ; //常量，标识缩略图左上角裁剪类型
    const TB5 =  5 ; //常量，标识缩略图右下角裁剪类型
    const TB6 =  6 ; //常量，标识缩略图固定尺寸缩放类型
    
	//打开图片
    public function __construct($imgFile) {
        if(!is_file($imgFile)){throw new \pgException('不存在的图像文件');}
        empty($this->img) || $this->img->destroy();
		$info = getimagesize($imgFile);
		if(empty($info)){throw new \pgException('图像格式错误无法解析');}
		if(!in_array($info['mime'], $this->allowType)){throw new \pgException('无法支持的文件格式');}
		switch($info['mime']) {
			case 'image/gif' : 
				$this->imgObj   = new gif($imgFile);
				$this->img      = imagecreatefromstring($this->imgObj->image());
				$this->exeName  = 'gif';
			break;
			case 'image/jpeg' : 
				$this->imgObj   = $this;
				$this->img      = imagecreatefromjpeg($imgFile);
				$this->exeName  = 'jpg';
			break;
			case 'image/png' : 
				$this->imgObj   = $this;
				$this->img      = imagecreatefrompng($imgFile);
				$this->exeName  = 'png';
			break;
			default:
				$this->imgObj   = $this;
				$this->img      = imagecreatefrombmp($imgFile);
				$this->exeName  = 'bmp';
		}
		$this->info = array(
			'width'   => $info[0],
			'height'  => $info[1],
		);
	}
	
	/**
     * 添加水印
     * @param  string  $source 水印图片路径
     * @param  integer $locate 水印位置
     * @param  integer $alpha  水印透明度
     */
    public function water($source, $locate = image::RB, $alpha = 80){
        if(!is_file($source)) throw new \pgException('水印图像不存在');
		//创建水印图像资源
        $info = getimagesize($source);
		if(empty($info)){throw new \pgException('水印文件格式错误');}
		if(!in_array($info['mime'], $this->allowType)){throw new \pgException('无法支持的水印文件格式');}
		switch($info['mime']) {
			case 'image/gif' : 
				throw new \pgException('水印文件不支持gif格式');
			break;
			case 'image/jpeg' : 
				$water = imagecreatefromjpeg($source);
			break;
			case 'image/png' : 
				$water = imagecreatefrompng($source);
			break;
			default:
				$water = imagecreatefrombmp($source);
		}
        imagealphablending($water, true);

        /* 设定水印位置 */
        switch ($locate) {
            /* 右下角水印 */
            case image::RB :
                $x = $this->info['width'] - $info[0];
                $y = $this->info['height'] - $info[1];
            break;
            /* 左下角水印 */
            case image::LB :
                $x = 0;
                $y = $this->info['height'] - $info[1];
			break;
            /* 左上角水印 */
            case image::LT :
                $x = $y = 0;
			break;
            /* 右上角水印 */
            case image::RT :
                $x = $this->info['width'] - $info[0];
                $y = 0;
			break;
            /* 居中水印 */
            case image::CC :
                $x = ($this->info['width'] - $info[0])/2;
                $y = ($this->info['height'] - $info[1])/2;
			break;
            /* 下居中水印 */
            case image::BC :
                $x = ($this->info['width'] - $info[0])/2;
                $y = $this->info['height'] - $info[1];
			break;
            /* 右居中水印 */
            case image::RC :
                $x = $this->info['width'] - $info[0];
                $y = ($this->info['height'] - $info[1])/2;
			break;
            /* 上居中水印 */
            case image::TC :
                $x = ($this->info['width'] - $info[0])/2;
                $y = 0;
			break;
            /* 左居中水印 */
           case image::LC :
                $x = 0;
                $y = ($this->info['height'] - $info[1])/2;
			break;
            default:
                /* 自定义水印坐标 */
                if(is_array($locate)){
                    list($x, $y) = $locate;
                }else {
                    throw new \pgException('不支持的水印位置类型');
                }
        }
        do{
            $src = imagecreatetruecolor($info[0], $info[1]);
            $color = imagecolorallocate($src, 255, 255, 255);
            imagefill($src, 0, 0, $color);
            imagecopy($src, $this->img, 0, 0, $x, $y, $info[0], $info[1]);
            imagecopy($src, $water, 0, 0, 0, 0, $info[0], $info[1]);
            imagecopymerge($this->img, $src, $x, $y, 0, 0, $info[0], $info[1], $alpha);
            imagedestroy($src);
        }
        while($this->exeName == 'gif' && $this->gifNext());
        imagedestroy($water);
    }

	/**
     * 生成缩略图
     * @param  integer $width  缩略图最大宽度
     * @param  integer $height 缩略图最大高度
     * @param  integer $type   缩略图裁剪类型
     */
    public function thumb($width, $height, $type = image::TB1) {
        $w = $this->info['width'];
        $h = $this->info['height'];
        switch ($type) {
            /* 等比例缩放 */
            case image::TB1 :
                if($w < $width && $h < $height) return;
                $scale = min($width/$w, $height/$h);
                $x = $y = 0;
                $width  = $w * $scale;
                $height = $h * $scale;
			break;
			/* 居中裁剪 */
            case image::TB3 :
                //计算缩放比例
                $scale = max($width/$w, $height/$h);
                $w = $width/$scale;
                $h = $height/$scale;
                $x = ($this->info['width'] - $w)/2;
                $y = ($this->info['height'] - $h)/2;
			break;
            /* 左上角裁剪 */
            case image::TB4 :
                $scale = max($width/$w, $height/$h);
                $x = $y = 0;
                $w = $width/$scale;
                $h = $height/$scale;
			break;
			/* 右下角裁剪 */
            case image::TB5 :
                $scale = max($width/$w, $height/$h);
                $w = $width/$scale;
                $h = $height/$scale;
                $x = $this->info['width'] - $w;
                $y = $this->info['height'] - $h;
			break;
            /* 填充 */
            case image::TB2 :
                if($w < $width && $h < $height){
                    $scale = 1;
                } else {
                    $scale = min($width/$w, $height/$h);
                }
                $neww = $w * $scale;
                $newh = $h * $scale;
                $posx = ($width  - $w * $scale)/2;
                $posy = ($height - $h * $scale)/2;
                do{
                    $img = imagecreatetruecolor($width, $height);
                    $color = imagecolorallocate($img, 255, 255, 255);
                    imagefill($img, 0, 0, $color);
                    imagecopyresampled($img, $this->img, $posx, $posy, 0, 0, $neww, $newh, $w, $h);
                    imagedestroy($this->img);
                    $this->img = $img;
                } while($this->exeName == 'gif' && $this->gifNext());
                
                $this->info['width']  = $width;
                $this->info['height'] = $height;
                return;
			//固定
            case image::TB6 :
                $x = $y = 0;
			break;
            default:
               throw new \pgException('不支持的缩略图裁剪类型');
        }
        $this->crop($w, $h, $x, $y, $width, $height);
	}

	/**
     * 图像添加文字
     * @param  string  $text   添加的文字
     * @param  string  $font   字体路径
     * @param  integer $size   字号
     * @param  string  $color  文字颜色
     * @param  integer $locate 文字写入位置
     * @param  integer $offset 文字相对当前位置的偏移量
     * @param  integer $angle  文字倾斜角度
     */
    public function text($text, $size, $color = array(0, 0, 0), $locate = image::RB, $offset = 0, $angle = 0, $font = null){
    	if(empty($font)){$font = PG_IN.'fonts'.PG_DS.'AMBROSIA.ttf';}
        if(!is_file($font)){throw new \pgException("不存在的字体文件：{$font}");}
        $info = imagettfbbox($size, $angle, $font, $text);
        $minx = min($info[0], $info[2], $info[4], $info[6]);
        $maxx = max($info[0], $info[2], $info[4], $info[6]); 
        $miny = min($info[1], $info[3], $info[5], $info[7]); 
        $maxy = max($info[1], $info[3], $info[5], $info[7]); 
        $x = $minx;
        $y = abs($miny);
        $w = $maxx - $minx;
        $h = $maxy - $miny;
        switch ($locate) {
            /* 右下角文字 */
            case image::RB :
                $x += $this->info['width']  - $w;
                $y += $this->info['height'] - $h;
			break;
            /* 左下角文字 */
            case image::LB :
                $y += $this->info['height'] - $h;
			break;
            /* 左上角文字 */
			case image::LT :
                // 起始坐标即为左上角坐标，无需调整
			break;
            /* 右上角文字 */
			case image::RT :
                $x += $this->info['width'] - $w;
			break;
            /* 居中文字 */
			case image::CC :
                $x += ($this->info['width']  - $w)/2;
                $y += ($this->info['height'] - $h)/2;
			break;
            /* 下居中文字 */
			case image::BC :
                $x += ($this->info['width'] - $w)/2;
                $y += $this->info['height'] - $h;
			break;
            /* 右居中文字 */
			case image::RC :
                $x += $this->info['width'] - $w;
                $y += ($this->info['height'] - $h)/2;
			break;
            /* 上居中文字 */
			case image::TC :
                $x += ($this->info['width'] - $w)/2;
			break;
            /* 左居中文字 */
			case image::LC :
                $y += ($this->info['height'] - $h)/2;
			break;
			/* 自定义文字坐标 */
            default:
                if(is_array($locate)){
                    list($posx, $posy) = $locate;
                    $x += $posx;
                    $y += $posy;
                }else { throw new \pgException('不支持的文字位置类型');}
        }

        if(is_array($offset)){
            $offset = array_map('intval', $offset);
            list($ox, $oy) = $offset;
        } else{
            $offset = intval($offset);
            $ox = $oy = $offset;
        }
		
        if(!is_array($color)){throw new \pgException('错误的颜色值');}
		
        do{
            $col = imagecolorallocatealpha($this->img, $color[0], $color[1], $color[2], 0);
            imagettftext($this->img, $size, $angle, $x + $ox, $y + $oy, $col, $font, $text);
        } while($this->exeName == 'gif' && $this->gifNext());
    }
	
	 /**
     * 裁剪图像
     * @param  integer $w      裁剪区域宽度
     * @param  integer $h      裁剪区域高度
     * @param  integer $x      裁剪区域x坐标
     * @param  integer $y      裁剪区域y坐标
     * @param  integer $width  图像保存宽度
     * @param  integer $height 图像保存高度
     */
    public function crop($w, $h, $x = 0, $y = 0, $width = null, $height = null) {
        empty($width)  && $width  = $w;
        empty($height) && $height = $h;
        do {
            $img = imagecreatetruecolor($width, $height);
            $color = imagecolorallocate($img, 255, 255, 255);
            imagefill($img, 0, 0, $color);
            imagecopyresampled($img, $this->img, 0, 0, $x, $y, $width, $height, $w, $h);
            imagedestroy($this->img); //销毁原图
            $this->img = $img;
        } while($this->exeName == 'gif' && $this->gifNext());
        $this->info['width']  = $width;
        $this->info['height'] = $height;
    }
	
	public function save($imgName, $quality = 100, $interlace = true) {
		switch($this->exeName){
			case 'gif':
				$saveUrl = $imgName.'.gif';
				$this->imgObj->save($imgName.'.gif');
			break;
			case 'jpg':
				$saveUrl = $imgName.'.jpg';
			 	imagejpeg($this->img, $imgName.'.jpg', $quality);
			break;
			case 'png':
				$saveUrl = $imgName.'.png';
			 	imagepng($this->img, $imgName.'.png', intval(9.99));
			break;
			default : 
				$saveUrl = $imgName.'.png';
			 	imagepng($this->img, $imgName.'.png', 9.99);
			break;
		}
		
		return $saveUrl;
	}
	
	private function gifNext(){
		$tmp = PG_IN.'tmp'.PG_DS.uniqid().'.gif';
        imagegif($this->img, $tmp);
        $this->imgObj->image(file_get_contents($tmp));
        $next = $this->imgObj->nextImage();
		unlink($tmp);
        if($next){
        	$this->img = imagecreatefromstring($next);
        	return $next;
        }else{
        	$this->img = imagecreatefromstring($this->imgObj->image());
        	return false;
        }
    }
	
    public function __destruct(){
        empty($this->img) || imagedestroy($this->img);
    }
}


/**
 * BMP 创建函数
 * @author simon
 * @param string $filename path of bmp file
 * @example who use,who knows
 * @return resource of GD
 */
function imagecreatefrombmp( $filename ) {
    if (!$f1 = fopen( $filename, "rb")) {return FALSE;}
    $FILE = unpack( "vfile_type/Vfile_size/Vreserved/Vbitmap_offset", fread( $f1, 14 ) );
    if ( $FILE['file_type'] != 19778 ){return FALSE;}
    $BMP = unpack( 'Vheader_size/Vwidth/Vheight/vplanes/vbits_per_pixel' . '/Vcompression/Vsize_bitmap/Vhoriz_resolution' . '/Vvert_resolution/Vcolors_used/Vcolors_important', fread( $f1, 40 ) );
    $BMP['colors'] = pow( 2, $BMP['bits_per_pixel'] );
    if ( $BMP['size_bitmap'] == 0 ) {$BMP['size_bitmap'] = $FILE['file_size'] - $FILE['bitmap_offset'];}
    $BMP['bytes_per_pixel'] = $BMP['bits_per_pixel'] / 8;
    $BMP['bytes_per_pixel2'] = ceil( $BMP['bytes_per_pixel'] );
    $BMP['decal'] = ($BMP['width'] * $BMP['bytes_per_pixel'] / 4);
    $BMP['decal'] -= floor( $BMP['width'] * $BMP['bytes_per_pixel'] / 4 );
    $BMP['decal'] = 4 - (4 * $BMP['decal']);
    if ( $BMP['decal'] == 4 ){$BMP['decal'] = 0;}
    $PALETTE = array();
    if ( $BMP['colors'] < 16777216 ){
        $PALETTE = unpack( 'V' . $BMP['colors'], fread( $f1, $BMP['colors'] * 4 ) );
    }

    $IMG = fread( $f1, $BMP['size_bitmap'] );
    $VIDE = chr( 0 );

    $res = imagecreatetruecolor( $BMP['width'], $BMP['height'] );
    $P = 0;
    $Y = $BMP['height'] - 1;
    while( $Y >= 0 ){
        $X = 0;
        while( $X < $BMP['width'] ){
            if ( $BMP['bits_per_pixel'] == 32 ){
                $COLOR = unpack( "V", substr( $IMG, $P, 3 ) );
                $B = ord(substr($IMG, $P,1));
                $G = ord(substr($IMG, $P+1,1));
                $R = ord(substr($IMG, $P+2,1));
                $color = imagecolorexact( $res, $R, $G, $B );
                if ( $color == -1 )
                    $color = imagecolorallocate( $res, $R, $G, $B );
                $COLOR[0] = $R*256*256+$G*256+$B;
                $COLOR[1] = $color;
            }elseif ( $BMP['bits_per_pixel'] == 24 )
                $COLOR = unpack( "V", substr( $IMG, $P, 3 ) . $VIDE );
            elseif ( $BMP['bits_per_pixel'] == 16 ){
                $COLOR = unpack( "n", substr( $IMG, $P, 2 ) );
                $COLOR[1] = $PALETTE[$COLOR[1] + 1];
            }elseif ( $BMP['bits_per_pixel'] == 8 ){
                $COLOR = unpack( "n", $VIDE . substr( $IMG, $P, 1 ) );
                $COLOR[1] = $PALETTE[$COLOR[1] + 1];
            }elseif ( $BMP['bits_per_pixel'] == 4 ){
                $COLOR = unpack( "n", $VIDE . substr( $IMG, floor( $P ), 1 ) );
                if ( ($P * 2) % 2 == 0 )
                    $COLOR[1] = ($COLOR[1] >> 4);
                else
                    $COLOR[1] = ($COLOR[1] & 0x0F);
                $COLOR[1] = $PALETTE[$COLOR[1] + 1];
            }elseif ( $BMP['bits_per_pixel'] == 1 ){
                $COLOR = unpack( "n", $VIDE . substr( $IMG, floor( $P ), 1 ) );
                if ( ($P * 8) % 8 == 0 )
                    $COLOR[1] = $COLOR[1] >> 7;
                elseif ( ($P * 8) % 8 == 1 )
                    $COLOR[1] = ($COLOR[1] & 0x40) >> 6;
                elseif ( ($P * 8) % 8 == 2 )
                    $COLOR[1] = ($COLOR[1] & 0x20) >> 5;
                elseif ( ($P * 8) % 8 == 3 )
                    $COLOR[1] = ($COLOR[1] & 0x10) >> 4;
                elseif ( ($P * 8) % 8 == 4 )
                    $COLOR[1] = ($COLOR[1] & 0x8) >> 3;
                elseif ( ($P * 8) % 8 == 5 )
                    $COLOR[1] = ($COLOR[1] & 0x4) >> 2;
                elseif ( ($P * 8) % 8 == 6 )
                    $COLOR[1] = ($COLOR[1] & 0x2) >> 1;
                elseif ( ($P * 8) % 8 == 7 )
                    $COLOR[1] = ($COLOR[1] & 0x1);
                $COLOR[1] = $PALETTE[$COLOR[1] + 1];
            }else
                return FALSE;
            imagesetpixel( $res, $X, $Y, $COLOR[1] );
            $X++;
            $P += $BMP['bytes_per_pixel'];
        }
        $Y--;
        $P += $BMP['decal'];
    }
    fclose($f1);
    return $res;
}

class gif{
	private $frames = array();
	// 每帧等待时间列表
	private $delays = array();
	// 构造方法，用于解码GIF图片
	public function __construct($src) {
			$src = file_get_contents($src);
			$de = new GIFDecoder($src);
			$this->frames = $de->GIFGetFrames();
			$this->delays = $de->GIFGetDelays();
	}

	// 设置或获取当前帧的数据
	public function image($stream = null){
		if(is_null($stream)){
			$current = current($this->frames);
			return false === $current ? reset($this->frames) : $current;
		} else {
			$this->frames[key($this->frames)] = $stream;
		}
	}

	// 将当前帧移动到下一帧
	public function nextImage(){
		return next($this->frames);
	}

	// 编码并保存当前GIF图片
	public function save($gifname){
		$gif = new GIFEncoder($this->frames, $this->delays, 0, 2, 0, 0, 0, 'bin');
		file_put_contents($gifname, $gif->GetAnimation());
	}

}

Class GIFEncoder {
	private $GIF = "GIF89a";		/* GIF header 6 bytes	*/
	private $VER = "GIFEncoder V2.05";	/* Encoder version		*/

	private $BUF = Array ( );
	private $LOP =  0;
	private $DIS =  2;
	private $COL = -1;
	private $IMG = -1;

	private $ERR = Array (
		'ERR00'	=>	"Does not supported function for only one image!",
		'ERR01'	=>	"Source is not a GIF image!",
		'ERR02'	=>	"Unintelligible flag ",
		'ERR03'	=>	"Does not make animation from animated GIF source",
	);

	public function __construct($GIF_src, $GIF_dly, $GIF_lop, $GIF_dis,$GIF_red, $GIF_grn, $GIF_blu, $GIF_mod) {
		if ( ! is_array ( $GIF_src ) && ! is_array ( $GIF_dly ) ) {
			printf	( "%s: %s", $this->VER, $this->ERR [ 'ERR00' ] );
			exit	( 0 );
		}
		$this->LOP = ( $GIF_lop > -1 ) ? $GIF_lop : 0;
		$this->DIS = ( $GIF_dis > -1 ) ? ( ( $GIF_dis < 3 ) ? $GIF_dis : 3 ) : 2;
		$this->COL = ( $GIF_red > -1 && $GIF_grn > -1 && $GIF_blu > -1 ) ?
						( $GIF_red | ( $GIF_grn << 8 ) | ( $GIF_blu << 16 ) ) : -1;

		for ( $i = 0; $i < count ( $GIF_src ); $i++ ) {
			if ( strToLower ( $GIF_mod ) == "url" ) {
				$this->BUF [ ] = fread ( fopen ( $GIF_src [ $i ], "rb" ), filesize ( $GIF_src [ $i ] ) );
			}
			else if ( strToLower ( $GIF_mod ) == "bin" ) {
				$this->BUF [ ] = $GIF_src [ $i ];
			}
			else {
				printf	( "%s: %s ( %s )!", $this->VER, $this->ERR [ 'ERR02' ], $GIF_mod );
				exit	( 0 );
			}
			if ( substr ( $this->BUF [ $i ], 0, 6 ) != "GIF87a" && substr ( $this->BUF [ $i ], 0, 6 ) != "GIF89a" ) {
				printf	( "%s: %d %s", $this->VER, $i, $this->ERR [ 'ERR01' ] );
				exit	( 0 );
			}
			for ( $j = ( 13 + 3 * ( 2 << ( ord ( $this->BUF [ $i ] { 10 } ) & 0x07 ) ) ), $k = TRUE; $k; $j++ ) {
				switch ( $this->BUF [ $i ] { $j } ) {
					case "!":
						if ( ( substr ( $this->BUF [ $i ], ( $j + 3 ), 8 ) ) == "NETSCAPE" ) {
							printf	( "%s: %s ( %s source )!", $this->VER, $this->ERR [ 'ERR03' ], ( $i + 1 ) );
							exit	( 0 );
						}
						break;
					case ";":
						$k = FALSE;
						break;
				}
			}
		}
		$this->GIFAddHeader ( );
		for ( $i = 0; $i < count ( $this->BUF ); $i++ ) {
			$this->GIFAddFrames ( $i, $GIF_dly [ $i ] );
		}
		$this->GIFAddFooter ( );
	}

	private function GIFAddHeader ( ) {
		$cmap = 0;

		if ( ord ( $this->BUF [ 0 ] { 10 } ) & 0x80 ) {
			$cmap = 3 * ( 2 << ( ord ( $this->BUF [ 0 ] { 10 } ) & 0x07 ) );

			$this->GIF .= substr ( $this->BUF [ 0 ], 6, 7		);
			$this->GIF .= substr ( $this->BUF [ 0 ], 13, $cmap	);
			$this->GIF .= "!\377\13NETSCAPE2.0\3\1" . $this->GIFWord ( $this->LOP ) . "\0";
		}
	}
	
	private function GIFAddFrames ( $i, $d ) {

		$Locals_str = 13 + 3 * ( 2 << ( ord ( $this->BUF [ $i ] { 10 } ) & 0x07 ) );

		$Locals_end = strlen ( $this->BUF [ $i ] ) - $Locals_str - 1;
		$Locals_tmp = substr ( $this->BUF [ $i ], $Locals_str, $Locals_end );

		$Global_len = 2 << ( ord ( $this->BUF [ 0  ] { 10 } ) & 0x07 );
		$Locals_len = 2 << ( ord ( $this->BUF [ $i ] { 10 } ) & 0x07 );

		$Global_rgb = substr ( $this->BUF [ 0  ], 13,
							3 * ( 2 << ( ord ( $this->BUF [ 0  ] { 10 } ) & 0x07 ) ) );
		$Locals_rgb = substr ( $this->BUF [ $i ], 13,
							3 * ( 2 << ( ord ( $this->BUF [ $i ] { 10 } ) & 0x07 ) ) );

		$Locals_ext = "!\xF9\x04" . chr ( ( $this->DIS << 2 ) + 0 ) .
						chr ( ( $d >> 0 ) & 0xFF ) . chr ( ( $d >> 8 ) & 0xFF ) . "\x0\x0";

		if ( $this->COL > -1 && ord ( $this->BUF [ $i ] { 10 } ) & 0x80 ) {
			for ( $j = 0; $j < ( 2 << ( ord ( $this->BUF [ $i ] { 10 } ) & 0x07 ) ); $j++ ) {
				if	(
						ord ( $Locals_rgb { 3 * $j + 0 } ) == ( ( $this->COL >> 16 ) & 0xFF ) &&
						ord ( $Locals_rgb { 3 * $j + 1 } ) == ( ( $this->COL >>  8 ) & 0xFF ) &&
						ord ( $Locals_rgb { 3 * $j + 2 } ) == ( ( $this->COL >>  0 ) & 0xFF )
					) {
					$Locals_ext = "!\xF9\x04" . chr ( ( $this->DIS << 2 ) + 1 ) .
									chr ( ( $d >> 0 ) & 0xFF ) . chr ( ( $d >> 8 ) & 0xFF ) . chr ( $j ) . "\x0";
					break;
				}
			}
		}
		switch ( $Locals_tmp { 0 } ) {
			case "!":
				$Locals_img = substr ( $Locals_tmp, 8, 10 );
				$Locals_tmp = substr ( $Locals_tmp, 18, strlen ( $Locals_tmp ) - 18 );
				break;
			case ",":
				$Locals_img = substr ( $Locals_tmp, 0, 10 );
				$Locals_tmp = substr ( $Locals_tmp, 10, strlen ( $Locals_tmp ) - 10 );
				break;
		}
		if ( ord ( $this->BUF [ $i ] { 10 } ) & 0x80 && $this->IMG > -1 ) {
			if ( $Global_len == $Locals_len ) {
				if ( $this->GIFBlockCompare ( $Global_rgb, $Locals_rgb, $Global_len ) ) {
					$this->GIF .= ( $Locals_ext . $Locals_img . $Locals_tmp );
				}
				else {
					$byte  = ord ( $Locals_img { 9 } );
					$byte |= 0x80;
					$byte &= 0xF8;
					$byte |= ( ord ( $this->BUF [ 0 ] { 10 } ) & 0x07 );
					$Locals_img { 9 } = chr ( $byte );
					$this->GIF .= ( $Locals_ext . $Locals_img . $Locals_rgb . $Locals_tmp );
				}
			}
			else {
				$byte  = ord ( $Locals_img { 9 } );
				$byte |= 0x80;
				$byte &= 0xF8;
				$byte |= ( ord ( $this->BUF [ $i ] { 10 } ) & 0x07 );
				$Locals_img { 9 } = chr ( $byte );
				$this->GIF .= ( $Locals_ext . $Locals_img . $Locals_rgb . $Locals_tmp );
			}
		}
		else {
			$this->GIF .= ( $Locals_ext . $Locals_img . $Locals_tmp );
		}
		$this->IMG  = 1;
	}

	private function GIFAddFooter ( ) {
		$this->GIF .= ";";
	}
	
	private function GIFBlockCompare ( $GlobalBlock, $LocalBlock, $Len ) {

		for ( $i = 0; $i < $Len; $i++ ) {
			if	(
					$GlobalBlock { 3 * $i + 0 } != $LocalBlock { 3 * $i + 0 } ||
					$GlobalBlock { 3 * $i + 1 } != $LocalBlock { 3 * $i + 1 } ||
					$GlobalBlock { 3 * $i + 2 } != $LocalBlock { 3 * $i + 2 }
				) {
					return ( 0 );
			}
		}

		return ( 1 );
	}
	
	private function GIFWord ( $int ) {

		return ( chr ( $int & 0xFF ) . chr ( ( $int >> 8 ) & 0xFF ) );
	}
	
	public function GetAnimation ( ) {
		return ( $this->GIF );
	}
}

Class GIFDecoder {
	private $GIF_buffer = Array ( );
	private $GIF_arrays = Array ( );
	private $GIF_delays = Array ( );
	private $GIF_stream = "";
	private $GIF_string = "";
	private $GIF_bfseek =  0;

	private $GIF_screen = Array ( );
	private $GIF_global = Array ( );
	private $GIF_sorted;
	private $GIF_colorS;
	private $GIF_colorC;
	private $GIF_colorF;

	public function __construct ( $GIF_pointer ) {
		$this->GIF_stream = $GIF_pointer;

		$this->GIFGetByte ( 6 );	// GIF89a
		$this->GIFGetByte ( 7 );	// Logical Screen Descriptor

		$this->GIF_screen = $this->GIF_buffer;
		$this->GIF_colorF = $this->GIF_buffer [ 4 ] & 0x80 ? 1 : 0;
		$this->GIF_sorted = $this->GIF_buffer [ 4 ] & 0x08 ? 1 : 0;
		$this->GIF_colorC = $this->GIF_buffer [ 4 ] & 0x07;
		$this->GIF_colorS = 2 << $this->GIF_colorC;

		if ( $this->GIF_colorF == 1 ) {
			$this->GIFGetByte ( 3 * $this->GIF_colorS );
			$this->GIF_global = $this->GIF_buffer;
		}
		
		for ( $cycle = 1; $cycle; ) {
			if ( $this->GIFGetByte ( 1 ) ) {
				switch ( $this->GIF_buffer [ 0 ] ) {
					case 0x21:
						$this->GIFReadExtensions ( );
						break;
					case 0x2C:
						$this->GIFReadDescriptor ( );
						break;
					case 0x3B:
						$cycle = 0;
						break;
				}
			}
			else {
				$cycle = 0;
			}
		}
	}
	
	private function GIFReadExtensions ( ) {
		$this->GIFGetByte ( 1 );
		for ( ; ; ) {
			$this->GIFGetByte ( 1 );
			if ( ( $u = $this->GIF_buffer [ 0 ] ) == 0x00 ) {
				break;
			}
			$this->GIFGetByte ( $u );
			if ( $u == 4 ) {
				$this->GIF_delays [ ] = ( $this->GIF_buffer [ 1 ] | $this->GIF_buffer [ 2 ] << 8 );
			}
		}
	}
	
	private function GIFReadDescriptor ( ) {
		$GIF_screen	= Array ( );

		$this->GIFGetByte ( 9 );
		$GIF_screen = $this->GIF_buffer;
		$GIF_colorF = $this->GIF_buffer [ 8 ] & 0x80 ? 1 : 0;
		if ( $GIF_colorF ) {
			$GIF_code = $this->GIF_buffer [ 8 ] & 0x07;
			$GIF_sort = $this->GIF_buffer [ 8 ] & 0x20 ? 1 : 0;
		}
		else {
			$GIF_code = $this->GIF_colorC;
			$GIF_sort = $this->GIF_sorted;
		}
		$GIF_size = 2 << $GIF_code;
		$this->GIF_screen [ 4 ] &= 0x70;
		$this->GIF_screen [ 4 ] |= 0x80;
		$this->GIF_screen [ 4 ] |= $GIF_code;
		if ( $GIF_sort ) {
			$this->GIF_screen [ 4 ] |= 0x08;
		}
		$this->GIF_string = "GIF87a";
		$this->GIFPutByte ( $this->GIF_screen );
		if ( $GIF_colorF == 1 ) {
			$this->GIFGetByte ( 3 * $GIF_size );
			$this->GIFPutByte ( $this->GIF_buffer );
		}
		else {
			$this->GIFPutByte ( $this->GIF_global );
		}
		$this->GIF_string .= chr ( 0x2C );
		$GIF_screen [ 8 ] &= 0x40;
		$this->GIFPutByte ( $GIF_screen );
		$this->GIFGetByte ( 1 );
		$this->GIFPutByte ( $this->GIF_buffer );
		for ( ; ; ) {
			$this->GIFGetByte ( 1 );
			$this->GIFPutByte ( $this->GIF_buffer );
			if ( ( $u = $this->GIF_buffer [ 0 ] ) == 0x00 ) {
				break;
			}
			$this->GIFGetByte ( $u );
			$this->GIFPutByte ( $this->GIF_buffer );
		}
		$this->GIF_string .= chr ( 0x3B );
		$this->GIF_arrays[] = $this->GIF_string;
	}

	private function GIFGetByte ( $len ) {
		$this->GIF_buffer = Array ( );

		for ( $i = 0; $i < $len; $i++ ) {
			if ( $this->GIF_bfseek > strlen ( $this->GIF_stream ) ) {
				return 0;
			}
			$this->GIF_buffer [ ] = ord ( $this->GIF_stream { $this->GIF_bfseek++ } );
		}
		return 1;
	}
	
	private function GIFPutByte ( $bytes ) {
		for ( $i = 0; $i < count ( $bytes ); $i++ ) {
			$this->GIF_string .= chr ( $bytes [ $i ] );
		}
	}
	
	public function GIFGetFrames ( ) {
		return ( $this->GIF_arrays );
	}
	
	public function GIFGetDelays ( ) {
		return ( $this->GIF_delays );
	}
}
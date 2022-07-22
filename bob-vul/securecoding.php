<?php
session_start();
include "./config.php";
if($_GET['page'] == "login"){
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    $db = dbconnect();
    
    # input filter
    $filter_id = mysqli_real_escape_string($db, $input['id']);
    $filter_pw = mysqli_real_escape_string($db, $input['pw']);
    
    # using sprintf in MYSQL query to separate variable
    $query = sprintf("select id,pw from member where id='%s'",$filter_id);
    $row = mysqli_query($db,$query);
    $result = mysqli_fetch_array($row);
    
    # apply hash(sha256) to intput pw
    $hash_pw = hash("sha256",$filter_pw);
    
    # admin info already in DATABASE. so pw is plaintext IN DB. First check admin id,pw and if pw is plaintext, update pw with sha256 in DB
    if($result['id'] == 'admin' && $hash_pw != $result['pw']){ 
        $result_pw = hash("sha256", $result['pw']);
        if($result_pw == $hash_pw){ 
            $query = sprintf("update member set pw='%s' where id='admin'",$result_pw);
            mysqli_query($db,$query);        
            
        }
    } else { $result_pw = $result['pw']; }
    
    if($result['id'] && $result_pw == $hash_pw){
        $_SESSION['id'] = $result['id'];
        exit("<script>alert(`login ok`);location.href=`/`;</script>");
    }
    else{ exit("<script>alert(`login fail`);history.go(-1);</script>"); }
}

function passwordCheck($_str)
{
    $pw = $_str;
    $num = preg_match('/[0-9]/u', $pw);
    $eng = preg_match('/[a-z]/u', $pw);
    $spe = preg_match("/[\!\@\#\$\%\^\&\*]/u",$pw);
 
    if(strlen($pw) < 10 || strlen($pw) > 30)
    {
        return array(false,"비밀번호는 영문, 숫자, 특수문자를 혼합하여 최소 10자리 ~ 최대 30자리 이내로 입력해주세요.");
        exit;
    }
 
    if(preg_match("/\s/u", $pw) == true)
    {
        return array(false, "비밀번호는 공백없이 입력해주세요.");
        exit;
    }
 
    if( $num == 0 || $eng == 0 || $spe == 0)
    {
        return array(false, "영문, 숫자, 특수문자를 혼합하여 입력해주세요.");
        exit;
    }
 
    return array(true);
}

if($_GET['page'] == "join"){
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    $db = dbconnect();
    
    if(strlen($input['id']) > 120) exit("<script>alert(`userid too long`);history.go(-1);</script>");
    if(strlen($input['email']) > 120) exit("<script>alert(`email too long`);history.go(-1);</script>");
    if(strlen($input['pw']) > 120) exit("<script>alert(`pw too long`);history.go(-1);</script>"); 
    if(!filter_var($input['email'],FILTER_VALIDATE_EMAIL)) exit("<script>alert(`wrong email`);history.go(-1);</script>");
 
    # input filter
    $filter_id = mysqli_real_escape_string($db, $input['id']);
    $filter_pw = mysqli_real_escape_string($db, $input['pw']);
    $filter_email=filter_var($input['email'], FILTER_SANITIZE_EMAIL);
    
    $query = sprintf("select id from member where id='%s'",$filter_id);
    
    $row = mysqli_query($db,$query);
    $result = mysqli_fetch_array($row);
    
    # check pw security level
    $cheack_pw = passwordCheck($filter_pw);
    
    if(!isset($result['id']) && check_pw){
        $hash_pw = hash("sha256",$filter_pw);
        $query = sprintf("insert into member values('%s','%s','%s','user')",$filter_id,$filter_email,$hash_pw);
        mysqli_query($db,$query);
        exit("<script>alert(`join ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`Userid already existed`);history.go(-1);</script>");
    }
}

if($_GET['page'] == "upload"){

    $filter_id = $_SESSION['id'];
    if(!isset($filter_id)){
        exit("<script>alert(`login plz`);history.go(-1);</script>");
    }
    if($_FILES['fileToUpload']['size'] >= 1024 * 1024 * 1){ 
        exit("<script>alert(`file is too big`);history.go(-1);</script>"); 
    } // file size limit(1MB). do not remove it.
    $extension = explode(".",$_FILES['fileToUpload']['name'])[1];
    
    if($extension == "txt" || $extension == "png"){
        system("cp {$_FILES['fileToUpload']['tmp_name']} ./upload/{$_FILES['fileToUpload']['name']}");
        exit("<script>alert(`upload ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`txt or png only`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "download"){
    $filter_file = htmlspecialchars($_GET['file']);
    $content = file_get_contents("./upload/{$filter_file}");

    if(!$content){
        exit("<script>alert(`not exists file`);history.go(-1);</script>");
    }
    else{
        header("Content-Disposition: attachment;");
        echo $content;
        exit;
    }
}
if($_GET['page'] == "admin"){
    $db = dbconnect();
    $filter_id = $_SESSION['id'];
    $session_id = mysqli_real_escape_string($db, $filter_id);
    
    if(isset($session_id)){
        $query = sprintf("select id from member where id='%s'",$session_id);
        $row = mysqli_query($db,$query);
        $result = mysqli_fetch_array($row);
    
        if($result['id'] == "admin"){
            echo htmlspecialchars(file_get_contents("/flag")); // do not remove it.
        }
        else{
            exit("<script>alert(`admin only`);history.go(-1);</script>");
        }
    }
    else{
            exit("<script>alert(`admin only`);history.go(-1);</script>");
    }
    
}

/*  this is hint. you can remove it.
CREATE TABLE `member` (
    `id` varchar(120) NOT NULL,
    `email` varchar(120) NOT NULL,
    `pw` varchar(120) NOT NULL,
    `type` varchar(5) NOT NULL
  );
  
  INSERT INTO `member` (`id`, `email`, `pw`, `type`)
      VALUES ('admin', '**SECRET**', '**SECRET**', 'admin');
*/

?>

<?php

namespace oauth\nodeloc;

class nodeloc
{
    private $clientId;
    private $clientSecret;
    private $redirectUri;

    public function meta()
    {
        return [
            'name'        => 'NodeLoc登录',
            'description' => '使用NodeLoc账号登录',
            'author'      => 'Mike Leone',
            'logo_url'    => 'nodeloc.svg',
        ];
    }

    public function config()
    {
        return [
            'Client ID' => [
                'type' => 'text',
                'name' => 'client_id',
                'desc' => 'NodeLoc OAuth 2.0 客户端 ID'
            ],
            'Client Secret' => [
                'type' => 'text',
                'name' => 'client_secret',
                'desc' => 'NodeLoc OAuth 2.0 客户端密钥'
            ],
        ];
    }

    public function url($params)
    {
        $this->clientId = $params['client_id'];
        $this->redirectUri = $params['callback'];

        $state = md5(uniqid(rand(), true));
        $authUrl = "https://conn.nodeloc.cc/oauth2/auth?";
        $authUrl .= http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid profile',
            'state' => $state,
        ]);

        return $authUrl;
    }

    public function callback($params)
    {
        $this->clientId = $params['client_id'];
        $this->clientSecret = $params['client_secret'];
        $this->redirectUri = $params['callback'];

        try {
            if (!isset($params['code'])) {
                throw new \Exception('Missing authorization code');
            }

            $code = $params['code'];

            // 获取访问令牌
            $tokenData = $this->getAccessToken($code);

            // 获取用户信息
            $userData = $this->getUserInfo($tokenData['access_token']);

            return [
                'openid' => $userData['sub'],
                'data' => [
                    'username' => $userData['username'] ?? '',
                    'sex' => '', // NodeLoc 不提供性别信息
                    'province' => '', // NodeLoc 不提供省份信息
                    'city' => '', // NodeLoc 不提供城市信息
                    'avatar' => '', // NodeLoc 不提供头像信息
                    'email' => $userData['email'] ?? '',
                ],
                'callbackBind' => 'all',
            ];

        } catch (\Exception $e) {
            error_log("NodeLoc OAuth Error: " . $e->getMessage());
            return [
                'error' => true,
                'message' => $e->getMessage()
            ];
        }
    }

    private function getAccessToken($code)
    {
        $tokenUrl = "https://conn.nodeloc.cc/oauth2/token";
        $postData = [
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'grant_type' => 'authorization_code'
        ];

        $response = $this->makeRequest($tokenUrl, $postData, true);
        $tokenData = json_decode($response, true);

        if (!isset($tokenData['access_token'])) {
            throw new \Exception('Failed to obtain access token: ' . print_r($tokenData, true));
        }

        return $tokenData;
    }

    private function getUserInfo($accessToken)
    {
        $userInfoUrl = "https://conn.nodeloc.cc/oauth2/userinfo";
        $headers = ['Authorization: Bearer ' . $accessToken];

        $response = $this->makeRequest($userInfoUrl, null, false, $headers);
        $userData = json_decode($response, true);

        if (!isset($userData['sub'])) {
            throw new \Exception('Failed to get user info: ' . print_r($userData, true));
        }

        return $userData;
    }

    private function makeRequest($url, $postData = null, $isPost = false, $headers = [])
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        if ($isPost) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        }

        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            throw new \Exception('Curl error: ' . curl_error($ch));
        }

        curl_close($ch);
        return $response;
    }
}

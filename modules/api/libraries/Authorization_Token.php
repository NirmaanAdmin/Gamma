<?php defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Authorization_Token
 * ----------------------------------------------------------
 * API Token Generate/Validation
 * 
 */
require_once __DIR__.'/../vendor/autoload.php';
use Firebase\JWT\JWT as api_JWT;
use Firebase\JWT\Key as api_Key;

class Authorization_Token 
{
    /**
     * Token Key
     */
    protected $token_key;

    /**
     * Token algorithm
     */
    protected $token_algorithm;

    /**
     * Token Request Header Name
     */
    protected $token_header;

    /**
     * Token Expire Time (default: 10 years)
     */
    protected $token_expire_time = 315569260; 

    public function __construct()
    {
        $this->CI =& get_instance();

        /** 
         * Load JWT config file
         */
        $this->CI->load->config('jwt');

        /**
         * Load Config Items Values 
         */
        $this->token_key        = $this->CI->config->item('jwt_key');
        $this->token_algorithm  = $this->CI->config->item('jwt_algorithm');
        $this->token_header     = $this->CI->config->item('token_header');
        $this->token_expire_time= $this->CI->config->item('token_expire_time');
    }

    /**
     * Generate Token
     * @param: {array} data
     */
    public function generateToken($data = null)
    {
        if ($data && is_array($data))
        {
            // Add API time key in user array
            $data['API_TIME'] = time();

            try {
                return api_JWT::encode($data, $this->token_key, $this->token_algorithm);
            } catch (Exception $e) {
                return 'Message: ' . $e->getMessage();
            }
        } else {
            return "Token Data Undefined!";
        }
    }

    /**
     * Retrieve token from headers
     */
    public function get_token()
    {
        $headers = $this->CI->input->request_headers();
        return $this->extractToken($headers);
    }

    /**
     * Validate Token from Headers
     * @return array
     */
    public function validateToken()
    {
        $headers = $this->CI->input->request_headers();
        $token_data = $this->tokenIsExist($headers);

        if ($token_data['status'] === TRUE) {
            try {
                $token_decode = api_JWT::decode($token_data['token'], new api_Key($this->token_key, $this->token_algorithm));

                if (!empty($token_decode) && is_object($token_decode)) {
                    // Validate API Time
                    if (!isset($token_decode->API_TIME) || !is_numeric($token_decode->API_TIME)) {
                        return ['status' => FALSE, 'message' => 'Token Time Not Defined!'];
                    }

                    // Check if token is expired
                    if ((time() - $token_decode->API_TIME) >= $this->token_expire_time) {
                        return ['status' => FALSE, 'message' => 'Token Expired.'];
                    }

                    return ['status' => TRUE, 'data' => $token_decode];

                } else {
                    return ['status' => FALSE, 'message' => 'Invalid Token Data.'];
                }

            } catch (Exception $e) {
                return ['status' => FALSE, 'message' => $e->getMessage()];
            }
        } else {
            return ['status' => FALSE, 'message' => $token_data['message']];
        }
    }

    /**
     * Check if Token Exists in Request Headers
     * @param array $headers
     * @return array
     */
    private function tokenIsExist($headers)
    {
        if (!empty($headers) && is_array($headers)) {
            foreach ($headers as $header_name => $header_value) {
                if (strtolower(trim($header_name)) == strtolower(trim($this->token_header))) {
                    // Support "Bearer" format
                    if (strpos(strtolower($header_value), 'bearer ') === 0) {
                        $header_value = trim(substr($header_value, 7)); // Remove "Bearer " prefix
                    }
                    return ['status' => TRUE, 'token' => $header_value];
                }
            }
        }
        return ['status' => FALSE, 'message' => 'Token is not defined.'];
    }

    /**
     * Extract token from headers
     * @param array $headers
     * @return string
     */
    private function extractToken($headers)
    {
        if (!empty($headers) && is_array($headers)) {
            foreach ($headers as $header_name => $header_value) {
                if (strtolower(trim($header_name)) == strtolower(trim($this->token_header))) {
                    // Support "Bearer" token
                    if (strpos(strtolower($header_value), 'bearer ') === 0) {
                        return trim(substr($header_value, 7)); // Remove "Bearer " prefix
                    }
                    return $header_value;
                }
            }
        }
        return 'Token is not defined.';
    }
}

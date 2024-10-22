<?php
/**
 * Fgsl Jwt - a JWT handler
 *
 * @author Flávio Gomes da Silva Lisboa <flavio.lisboa@fgsl.eti.br.br>
 * @link https://github.com/fgsl/jwt for the canonical source repository
 * @copyright Copyright (c) 2019 FGSL (http://www.fgsl.eti.br)
 * @license https://www.gnu.org/licenses/agpl.txt GNU AFFERO GENERAL PUBLIC LICENSE
 */
declare(strict_types = 1);
namespace Fgsl\Jwt;

class Jwt
{
    private array $alg;
    private string$typ;
    private string $iss;
    private string $expiresAt;
    private ?string $privateKeyLocation;
    
    /**
     * @param array  $alg                   algorithm
     * @param string $typ                   token type
     * @param string $iss                   issuer
     * @param string $expiresAt             UNIX timestamp for token expiration
     * @param string $privateKeyLocation    path of filesystem for private key file
     */    
    public function __construct(array $alg, string $typ, string $iss, string $expiresAt, string $privateKeyLocation = null)
    {
        $this->alg = $alg;
        $this->typ = $typ;
        $this->iss = $iss;
        $this->expiresAt = $expiresAt;
        $this->privateKeyLocation = $privateKeyLocation;
    }

    /**
     * @param string $subject                       token subject
     * @param string $credential                    user credential
     * @param array $payloadAdditionalParameters    claims
     * @return string
     */
    public function getBearerToken(string $subject, string $credential = null, array $payloadAdditionalParameters = null): string
    {
        $header = [
            'alg' => $this->alg[0],
            'typ' => $this->typ
        ];
        $header = json_encode($header);
        $header = base64_encode($header);
        $date = date_create();
        $iat = date_timestamp_get($date);
        $date->add(new \DateInterval($this->expiresAt));
        $exp = date_timestamp_get($date);
        $payload = [
            'exp' => $exp,
            'iat' => $iat,
            'iss' => $this->iss,
            'sub' => $subject
        ];
        if (!is_null($payloadAdditionalParameters)){
            $payload = array_merge($payload,$payloadAdditionalParameters);
        }
        $payload = json_encode($payload);
        $payload = base64_encode($payload);
        $rsaPrivateKey = (is_null($credential) ? file_get_contents($this->privateKeyLocation) : $credential);
        $signature = hash_hmac($this->alg[1], "$header.$payload", $rsaPrivateKey, true);
        $signature = base64_encode($signature);
        return "$header.$payload.$signature";
    }
    
    /**
     * @param string $token
     * @return object
     * @throws \Exception
     */
    public static function getPayload(string $token): object
    {
        $part = explode(".",$token);
        if (count($part)<3){
            throw new \Exception('token has not enough parts:' . count($part));
        }
        return json_decode(base64_decode($part[1]));
    }
    
    /**
     * @param string $token
     * @return bool
     */
    public static function expired(string $token): bool
    {
        $payload = self::getPayload($token);
        if ($payload == false){
            return true;
        }
        $currentTimestamp = date_timestamp_get(date_create());
        if ($currentTimestamp > $payload->exp){
            return true;
        }
        return false;        
    }    
}
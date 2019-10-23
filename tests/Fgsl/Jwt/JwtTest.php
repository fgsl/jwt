<?php

use PHPUnit\Framework\TestCase;
use Fgsl\Jwt\Jwt;

/**
 *  test case.
 */
class JwtTest extends TestCase
{
    public function testBearerToken()
    {
        $jwt = new Jwt(['RS256','sha256'], 'JWT', 'newbraveworld.com', 'PT2H');
        
        $bearerToken = $jwt->getBearerToken('foouser','baapassword');
        
        $this->assertTrue(is_string($bearerToken));
        $this->assertNotEmpty($bearerToken);
        
        $payload = Jwt::getPayload($bearerToken);        
   
        $this->assertTrue(is_object($payload));        
    }    
}
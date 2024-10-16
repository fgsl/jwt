<?php

use PHPUnit\Framework\TestCase;
use Fgsl\Jwt\Jwt;

class JwtTest extends TestCase
{
    /**
     * @covers Jwt
     */
    public function testBearerToken()
    {
        $jwt = new Jwt(['RS256','sha256'], 'JWT', 'newbraveworld.com', 'PT2H');
        
        $bearerToken = $jwt->getBearerToken('foouser','baapassword',['role' => 'admin']);
        
        $this->assertTrue(is_string($bearerToken));
        $this->assertNotEmpty($bearerToken);
        
        $payload = Jwt::getPayload($bearerToken);
   
        $this->assertTrue(is_object($payload));
        
        $this->assertEquals('foouser', $payload->sub);
        $this->assertEquals('newbraveworld.com', $payload->iss);
        $this->assertEquals('admin',$payload->role);
        
        $this->assertFalse(Jwt::expired($bearerToken));
    }    
}
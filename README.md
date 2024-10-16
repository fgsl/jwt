# Fgsl JWT

For creating a JWT token, you must before create an instance of `Fgsl\Jwt\Jwt`. After, you call method `getBearerToken`. This method will store the username in the token as the `sub` attribute. Additional attributes can be sent in an array as the third argument.

For recovering the payload from a given token, call the static method `getPayload`.

You can see a use example below. You can run this test from [JwtTest](./tests/Fgsl/Jwt/JwtTest.php) class using PHPUnit.

```php
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
```    


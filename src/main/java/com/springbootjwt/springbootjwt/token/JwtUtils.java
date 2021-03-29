package com.springbootjwt.springbootjwt.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.springbootjwt.springbootjwt.entity.Payment;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

@Component
@Slf4j
public class JwtUtils {

    private ObjectMapper objectMapper;

    @Autowired
    public JwtUtils(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Value("${token.secret}")
    private String tokenSecret;
    @Value("${token.issuer}")
    private String tokenIssuer;
    @Value("${token.expiration.millis}")
    private String tokenExpiration;
    @Value("${token.subject}")
    private String tokenSubject;

    public String generateToken(Payment payment) throws JsonProcessingException {

        long timeStamp = System.currentTimeMillis();
        String data = objectMapper.writeValueAsString(payment);
        HashMap<String, Object> claims = new HashMap<>();

        Date issueAt = new Date(timeStamp);
        Date expiry = new Date(timeStamp + Long.parseLong(tokenExpiration));

        claims.put("payload", data);

        byte[] secret = tokenSecret.getBytes();

        log.info("Issued At " + issueAt);
        return Jwts.builder().setId(UUID.randomUUID().toString())
                .setClaims(claims)
                .setIssuedAt(issueAt)
                .setIssuer(tokenIssuer)
                .setSubject(tokenSubject)
                .setExpiration(expiry)
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public String validateToken(String jwt) {
        String payload = null;
        try {
            byte[] secret = tokenSecret.getBytes();
            Claims claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(jwt).getBody();
             payload = (String) claims.get("payload");
            log.info("Id:" + claims.getId() + " IssuedAt: " + claims.getIssuedAt() +
                    " ExpirationDate: " + claims.getExpiration() +
                    " Issuer:" + claims.getIssuer() + " Subject: " + claims.getSubject());
        } catch (Exception e){
           throw new ExpiredJwtException(null,null,"Jwt Timeout exception",e.getCause());
        }

        return payload;
    }
}

package com.springbootjwt.springbootjwt.resource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.springbootjwt.springbootjwt.entity.Payment;
import com.springbootjwt.springbootjwt.entity.Token;
import com.springbootjwt.springbootjwt.token.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/token")
public class PaymentResource {


    @Autowired
    public JwtUtils jwtUtils;

    @PostMapping("/validate")
    public String getPayment(@RequestBody Token jsonWebToken) {
        return jwtUtils.validateToken(jsonWebToken.getTokenGenerated());
    }

    @PostMapping("/generate")
    public Token getPayment(@RequestBody Payment payment) throws JsonProcessingException {
        String s = jwtUtils.generateToken(payment);
        return new Token(s);
    }
}

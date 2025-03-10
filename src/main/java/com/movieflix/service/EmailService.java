package com.movieflix.service;

import com.movieflix.dto.MailBody;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmailService {

    private final JavaMailSender javaMailSender;

    public EmailService(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    public void sendSimpleMessage(MailBody mailBody) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(mailBody.to());
        message.setFrom("ak2057338@gmail.com");
        message.setSubject(mailBody.subject());
        message.setText(mailBody.text());

        javaMailSender.send(message);
    }
    public void sendNotificationToAllUsers(List<String> userEmails, String movieTitle) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("New Movie Added!");
        message.setText("A new movie '" + movieTitle + "' has been added to our collection. Check it out!");

        for (String email : userEmails) {
            message.setTo(email);
            javaMailSender.send(message);
        }
    }
}

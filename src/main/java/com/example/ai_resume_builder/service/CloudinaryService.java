package com.example.ai_resume_builder.service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@Service
public class CloudinaryService {

    private final Cloudinary cloudinary;

    public CloudinaryService() {
        String cloudName = "dheuurohu";
        String apiKey = "188488441947215";
        String apiSecret = "wKKxURCKNcywoI4TOcQ32La2dDA";

        try {
            this.cloudinary = new Cloudinary(ObjectUtils.asMap(
                    "cloud_name", cloudName,
                    "api_key", apiKey,
                    "api_secret", apiSecret
            ));
            System.out.println("Cloudinary Service initialized successfully.");
        } catch (Exception e) {
            System.err.println("Error initializing Cloudinary service: " + e.getMessage());
            throw new RuntimeException("Cloudinary initialization failed", e);
        }
    }

    public String uploadFile(MultipartFile file) throws IOException {
        // Assuming the method you need for file upload
        Map uploadResult = cloudinary.uploader().upload(file.getBytes(), ObjectUtils.emptyMap());
        return (String) uploadResult.get("url");
    }
}

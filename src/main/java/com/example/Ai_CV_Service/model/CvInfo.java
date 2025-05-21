package com.example.Ai_CV_Service.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class CvInfo {
    private String name;
    private String education;
    private String experience;
    private String skills;
    private String certifications;
}
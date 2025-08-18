# PDF Digital Signer

## Overview

PDF Digital Signer is a PHP-based web application that allows users to digitally sign PDF documents using PKCS12 digital certificates (P12/PFX files). Built using the SAPP library for PDF processing, the application provides a clean, user-friendly interface for uploading PDF files and certificate files, then processes them to create digitally signed documents. The system features real-time progress tracking, comprehensive file validation, and automatic cleanup to ensure secure and reliable document signing without data persistence.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes (August 14, 2025)

✓ Converted project from Python Flask to PHP architecture
✓ Integrated SAPP library for PDF digital signing
✓ Implemented PHP backend with Composer package management
✓ Set up PHP development server on port 5000
✓ Successfully tested application serving and interface

## System Architecture

### Frontend Architecture
- **Single-Page Application**: Built with vanilla JavaScript using a class-based architecture
- **Progressive Enhancement**: Core functionality implemented in the `PDFSigner` class with event-driven interactions
- **Bootstrap Framework**: Utilizes Bootstrap for responsive UI components and styling
- **File Validation**: Client-side validation for file types (PDF, P12/PFX) and size limits (50MB maximum)
- **Real-time Feedback**: Progress tracking system with visual indicators and error handling

### User Interface Design
- **Card-based Layout**: Clean card interface with hover effects and smooth transitions
- **Form Handling**: Comprehensive form validation with immediate feedback
- **Progress Visualization**: Built-in progress bars and loading spinners for user feedback
- **Responsive Design**: Mobile-friendly interface using Bootstrap's grid system

### File Processing Workflow
- **Multi-step Process**: Structured workflow starting with file upload and progressing through signing
- **Session Management**: Session-based tracking for maintaining state during processing
- **Error Handling**: Comprehensive error messaging and validation feedback

### Security Considerations
- **File Type Restrictions**: Strict validation of allowed file extensions
- **Size Limitations**: File size constraints to prevent abuse
- **Certificate Handling**: Secure processing of digital certificates (P12/PFX format)

## External Dependencies

### Frontend Libraries
- **Bootstrap**: CSS framework for responsive design and UI components
- **Native Browser APIs**: File API for file handling and form validation

### File Format Support
- **PDF Processing**: Handles PDF document input for signing
- **Digital Certificates**: Supports P12 and PFX certificate formats
- **Cross-browser Compatibility**: Relies on standard web APIs for broad browser support

### Potential Backend Integration
- **File Upload Endpoint**: Requires backend service for file processing
- **Digital Signing Service**: Backend integration needed for actual PDF signing operations
- **Session Management**: Server-side session handling for progress tracking
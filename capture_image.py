import cv2

def capture_image():
    """Capture an image from the webcam."""
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        raise RuntimeError("Unable to access the camera.")

    cv2.namedWindow("Capture Image")

    while True:
        ret, frame = cap.read()
        if not ret:
            raise RuntimeError("Failed to capture image.")
        
        # Overlay text on the frame
        font = cv2.FONT_HERSHEY_SIMPLEX
        text = "Press 'q' to capture the image."
        frame = cv2.putText(frame, text, (10, 30), font, 1, (255, 255, 255), 2, cv2.LINE_AA)
        
        cv2.imshow("Capture Image", frame)
        
        if cv2.waitKey(1) & 0xFF == ord('q'):
            cv2.imwrite('captured_image.jpg', frame)
            break

    cap.release()
    cv2.destroyAllWindows()
    return 'captured_image.jpg'

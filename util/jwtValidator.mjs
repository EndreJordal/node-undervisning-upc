import jwt from "jsonwebtoken";

const jwtValidator = (req, res, next) => {
  // Get the token from the request headers
  const authHeader = req.headers.authorization;

  // Check if token is present
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  // Extract token
  const token = authHeader.slice(7); // Remove 'Bearer ' from the beginning

  // Verify token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    } else {
      // Token is valid, attach decoded payload to request object
      req.user = decoded;
      next();
    }
  });
};
export default jwtValidator;

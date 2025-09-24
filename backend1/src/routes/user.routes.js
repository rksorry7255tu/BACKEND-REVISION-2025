import { Router } from "express";
import {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  updateUserAvatar,
  updateAccountDetails,
  currentUser,
  changeCurrentPassword,
  updateUsercoverImage,
  getUserChannelProfile,
} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
  upload.fields([
    {
      name: "avatar",
      maxCount: 1,
    },
    {
      name: "coverImage",
      maxCount: 1,
    },
  ]),
  registerUser
); //completed
router.route("/login").post(loginUser); //completed
router.route("/logout").post(verifyJWT, logoutUser); //completed
router.route("/refresh-token").post(refreshAccessToken); //completed
router.route("/changeCurrentPassword").post(verifyJWT, changeCurrentPassword); //completed
router.route("/currentUser").get(verifyJWT, currentUser); //completed
router.route("/updateAccountDetails").post(verifyJWT, updateAccountDetails); //complete
router.route("/updateUserAvatar").patch(
  upload.fields([
    {
      name: "avatar",
      maxCount: 1,
    },
  ]),
  verifyJWT,
  updateUserAvatar
); //complete
router.route("/updateUserCoverImage").patch(
  upload.fields([
    {
      name: "coverImage",
      maxCount: 1,
    },
  ]),
  verifyJWT,
  updateUsercoverImage
); //complete
router.route("/getUserChannelProfile").get(getUserChannelProfile);
export default router;

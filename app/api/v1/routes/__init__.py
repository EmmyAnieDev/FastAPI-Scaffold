from fastapi import APIRouter
from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.profile import router as user_router


router = APIRouter(prefix="/v1")
router.include_router(auth_router)
router.include_router(user_router)
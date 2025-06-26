from src.model.database import Specification, Products, db, ProductImages


def update_product_specifications(product_id, specifications):
    product = Products.query.get(product_id)
    if not product:
        return None
    for specification in specifications:
        if specification["id"]:
            specs_obj = Specification.query.filter(
                Specification.id == specification["id"]
            ).first()
            if specs_obj:
                specs_obj.name = specification["name"] or specs_obj.name
                specs_obj.description = (
                    specification["description"] or specs_obj.description
                )
                db.session.commit()
        else:
            specs_obj = Specification(
                name=specification["name"], description=specification["description"]
            )
            db.session.add(specs_obj)
    db.session.commit()
    return product


def update_product_images(product_id, images):
    product = Products.query.get(product_id)
    if not product:
        return None
    for image in images:
        if isinstance(image, dict):
            if image["id"]:
                image_obj = ProductImages.query.filter(
                    ProductImages.id == image["id"]
                ).first()
                if image_obj:
                    image_obj.image = image["image"] or image_obj.image
                    db.session.commit()
        elif isinstance(image, str):
            image_obj = ProductImages(image=image, product_id=product_id)
            db.session.add(image_obj)
    db.session.commit()
    return product

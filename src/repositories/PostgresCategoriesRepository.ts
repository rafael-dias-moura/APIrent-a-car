import { Category } from "../model/Category";
import {
    ICategoriesRepository,
    ICreateCategoryDTO,
} from "./ICategoriesRepository";

class PostgresCategoriesRepository implements ICategoriesRepository {
    findByName(name: string): Category {
        // throw new Error("Method not implemented.");
        console.log(name);
        return null;
    }
    list(): Category[] {
        // throw new Error("Method not implemented.");
        return null;
    }
    create({ name, description }: ICreateCategoryDTO): void {
        // throw new Error("Method not implemented.");
        console.log(name, description);
    }
}

export { PostgresCategoriesRepository };

import Role from "./models/role.js";

const seedRoles = async () => {
  await Role.bulkCreate([
    { name: "Public User" },
    { name: "Sub Admin" },
    { name: "Admin" },
  ]);
};

export default seedRoles;
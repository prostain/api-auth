"use strict";
module.exports = {
    up: async(queryInterface, Sequelize) => {
        await queryInterface.createTable("Users", {
            id: {
                allowNull: false,
                autoIncrement: true,
                primaryKey: true,
                type: Sequelize.INTEGER,
            },
            pseudo: {
                type: Sequelize.STRING,
            },
            firstname: {
                type: Sequelize.STRING,
            },
            lastname: {
                type: Sequelize.STRING,
            },
            email: {
                type: Sequelize.STRING,
            },
            password: {
                type: Sequelize.STRING,
            },
            address: {
                type: Sequelize.STRING,
            },
            postalCode: {
                type: Sequelize.STRING,
            },
            city: {
                type: Sequelize.STRING,
            },
            country: {
                type: Sequelize.STRING,
            },
            isActive: {
                type: Sequelize.BOOLEAN,
            },
            resetPasswordToken: {
                type: Sequelize.STRING(500),
            },
            googleToken: {
                type: Sequelize.TEXT,
            },
            appleToken: {
                type: Sequelize.TEXT,
            },
            roleId: {
                type: Sequelize.INTEGER,
                allowNull: false,
                foreignKey: true,
                references: {
                    model: "Roles",
                    key: "id",
                },
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE,
            },
            updatedAt: {
                allowNull: false,
                type: Sequelize.DATE,
            },
        });
    },
    down: async(queryInterface, Sequelize) => {
        await queryInterface.dropTable("Users");
    },
};